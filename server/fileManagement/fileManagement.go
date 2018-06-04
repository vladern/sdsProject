package fileManagement

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/sdsProject/server/models"

	"github.com/sdsProject/server/fileReader"

	"github.com/sdsProject/server/authentication"
	"github.com/segmentio/ksuid"
)

func init() {
	file, _ := os.OpenFile("./logs/logrus.log", os.O_CREATE|os.O_WRONLY, 0666)
	log.SetOutput(file)
}

// Upload recibe y guarda el archivo que ha mandado el cliente
func Upload(w http.ResponseWriter, r *http.Request) {
	// extract claims and verify the token
	claims, auth := authentication.ExtractClaims(r.Header.Get("Authorization"))
	if !auth {
		http.Error(w, "Invalid token, Unauthorized", 401)
		return
	}

	if r.Method == "GET" {
		crutime := time.Now().Unix()
		h := md5.New()
		io.WriteString(h, strconv.FormatInt(crutime, 10))
		token := fmt.Sprintf("%x", h.Sum(nil))

		t, _ := template.ParseFiles("upload.gtpl")
		t.Execute(w, token)
	} else {
		r.ParseMultipartForm(32 << 20)
		file, handler, err := r.FormFile("uploadfile")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()

		// log
		log.Println("User: " + claims.Email + " uploaded file: " + handler.Filename)

		// genero el ID 'único' para el archivo
		Filename := ksuid.New()
		user, existUser := fileReader.GetUserFromDataBase(claims.Email)
		if !existUser {
			http.Error(w, "Invalid token, Unauthorized", 401)
			log.Println("User do not exist: " + claims.Email + " func Upload()")
			return
		}

		// write file
		fmt.Fprintf(w, "%v", handler.Header)
		f, err := os.OpenFile("./files/"+Filename.String(), os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			log.Println("Write error uploading file: " + err.Error())
			return
		}
		defer f.Close()
		io.Copy(f, file)

		// añado la información del fichero con la información del usuario
		user.FilesInfo = append(user.FilesInfo, models.FileInfo{ID: Filename.String(), Name: handler.Filename})
		// actualizo la BBDD
		fileReader.UpdateUserIntoDataBase(user)
	}
}

// Download recibe el nombre del archivo a descargar y lo devuelve al cliente
func Download(writer http.ResponseWriter, request *http.Request) {
	// extract claims and verify the token
	claims, auth := authentication.ExtractClaims(request.Header.Get("Authorization"))
	if !auth {
		http.Error(writer, "Invalid token, Unauthorized", 401)
		return
	}
	//First of check if Get is set in the URL
	Filename := request.URL.Query().Get("file")
	if Filename == "" {
		//Get not set, send a 400 bad request
		http.Error(writer, "Get 'file' not specified in url.", 400)
		log.Println("Get 'file' not specified in url while downloading")
		return
	}

	// log
	log.Println("User: " + claims.Email + " downloaded file: " + Filename)

	// busco el usuario en la BBDD
	user, existUser := fileReader.GetUserFromDataBase(claims.Email)
	if !existUser {
		http.Error(writer, "Invalid token, Unauthorized", 401)
		log.Println("User do not exist in BBDD, while downloading")
		return
	}

	// busco el ID del archivo en la BBDD
	ID, found := fileReader.GetFileIDFromUser(Filename, user)
	if !found {
		//File not found, send 404
		http.Error(writer, "File not found.", 404)
		log.Println("File ID not found in BBDD while downloading")
		return
	}

	//Check if file exists and open
	Openfile, err := os.Open("./files/" + ID)
	defer Openfile.Close() //Close after function return
	if err != nil {
		//File not found, send 404
		http.Error(writer, "File not found.", 404)
		log.Println("File not found in memory while downloading")
		return
	}

	//File is found, create and send the correct headers

	//Get the Content-Type of the file
	//Create a buffer to store the header of the file in
	FileHeader := make([]byte, 512)
	//Copy the headers into the FileHeader buffer
	Openfile.Read(FileHeader)
	//Get content type of file
	FileContentType := http.DetectContentType(FileHeader)

	//Get the file size
	FileStat, _ := Openfile.Stat()                     //Get info from file
	FileSize := strconv.FormatInt(FileStat.Size(), 10) //Get file size as a string

	//Send the headers
	writer.Header().Set("Content-Disposition", "attachment; filename="+Filename)
	writer.Header().Set("Content-Type", FileContentType)
	writer.Header().Set("Content-Length", FileSize)

	//Send the file
	//We read 512 bytes from the file already so we reset the offset back to 0
	Openfile.Seek(0, 0)
	io.Copy(writer, Openfile) //'Copy' the file to the client
	return
}

// ListFiles devulelve el listado de archivos que tiene guardado un usuario en el servidor
func ListFiles(w http.ResponseWriter, r *http.Request) {
	// extract claims and verify the token
	claims, auth := authentication.ExtractClaims(r.Header.Get("Authorization"))
	if !auth {
		http.Error(w, "Invalid token, Unauthorized", 401)
		return
	}

	user, ok := fileReader.GetUserFromDataBase(claims.Email)
	if !ok {
		http.Error(w, "User dosn't exist, Unauthorized", 401)
		log.Println("User do not found in BBDD wile Listing Files")
		return
	} else {
		w.WriteHeader(http.StatusOK)
		json, _ := json.Marshal(user.FilesInfo)
		log.Println("Listed Files : " + user.Email)
		w.Write(json)
	}
}

// DeleteFile borra el archivo de un usuario guardado en el servidor
func DeleteFile(w http.ResponseWriter, r *http.Request) {
	// extract claims and verify the token
	claims, auth := authentication.ExtractClaims(r.Header.Get("Authorization"))
	if !auth {
		http.Error(w, "Invalid token, Unauthorized", 401)
		return
	}

	user, ok := fileReader.GetUserFromDataBase(claims.Email)
	if !ok {
		http.Error(w, "User dosn't exist, Unauthorized", 401)
		return
	} else {
		//First of check if Get is set in the URL
		Filename := r.URL.Query().Get("file")

		//Validate that file exists
		fileID, exist := fileReader.GetFileIDFromUser(Filename, user)
		if !exist {
			http.Error(w, "File not found !", 403)
			return
		}

		err := os.Remove("files/" + fileID)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, "Service Unavailable !", 503)
			return
		}

		// remove the file from BBDD
		for i := 0; i < len(user.FilesInfo); i++ {
			if user.FilesInfo[i].ID == fileID {
				user.FilesInfo = user.FilesInfo[:i+copy(user.FilesInfo[i:], user.FilesInfo[i+1:])]
			}
		}
		fileReader.UpdateUserIntoDataBase(user)

		// return the response
		w.Write([]byte("File was deleted !!"))
		log.Println("A file was deleted: " + fileID)
	}
}
