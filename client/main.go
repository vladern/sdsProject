package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/howeyc/gopass"

	"github.com/sdsProject/client/cryptoVladernn"
)

var (
	token string
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		color.Red(e.Error())
		panic(e)
	}
}

func main() {
	client()
}

// FileInfo information
type FileInfo struct {
	Name string `json:"name,omitempty"`
}

/***
CLIENTE
***/

// gestiona el modo cliente
func client() {
	var election string
	var finalizado bool
	finalizado = false
	for !finalizado {
		finalizado = true
		color.Cyan("-----------MENÚ-------------")
		fmt.Println("1.Login")
		fmt.Println("2.Sign In")
		fmt.Print("Que quieres hacer ?:(1 o 2) ")
		fmt.Scanf("%s\n", &election)

		if election == "1" {
			login()
		} else if election == "2" {
			signin()
		} else {
			color.Red("Opción no válida, vuelve a intentarlo")
			finalizado = false
		}
	}
}

func uploadFile() {
	var election string
	color.Cyan("-----------Subida del archivo seguro-------------")
	fmt.Print("Ruta del archivo que quieras subir: ")
	fmt.Scanf("%s\n", &election)

	err := postFile(election, "https://localhost:10443/upload", token)
	chk(err)
}

func login() {
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// # Login
	var email string
	var pin string
	fmt.Print("Introduce tu email: ")
	fmt.Scanf("%s\n", &email)
	fmt.Print("Introduce tu contraseña: ")
	password, err := gopass.GetPasswdMasked() // Masked

	hashBase64 := encryptPassword(string(password))

	data := url.Values{}             // estructura para contener los valores
	data.Set("email", email)         // comando (string)
	data.Set("password", hashBase64) // usuario (string)

	r, err := client.PostForm("https://localhost:10443/login", data) // enviamos por POST
	if err != nil {
		color.Red("Error de validación")
		return
	}

	if r.StatusCode == 200 {
		// pido eque introduzca el pin
		color.Cyan("Introduce el pin que se te ha enviado por correo: ")
		fmt.Scanf("%s\n", &pin)

		data1 := url.Values{}
		data1.Set("email", email)
		data1.Set("pin", pin)

		r1, err := client.PostForm("https://localhost:10443/verficarPin", data1)
		chk(err)

		fmt.Println("Respuesta:")
		body, err := ioutil.ReadAll(r1.Body)
		chk(err)
		token = string(body)

		var election string
		var finalizado = false
		for !finalizado {
			fmt.Println("-----------MENÚ-------------")
			fmt.Println("1.Subir un archivo")
			fmt.Println("2.Bajar un arvhivo")
			fmt.Println("3.Listado de archivos")
			fmt.Println("4.Borrar un archivo")
			fmt.Print("Que quieres hacer ?:(1, 2, 3 o 4) ")
			fmt.Scanf("%s\n", &election)

			if election == "1" {
				uploadFile()
			} else if election == "2" {
				fmt.Print("Nombre del archivo: ")
				fmt.Scanf("%s\n", &election)
				downloadFromURL("https://localhost:10443/download/?file=" + election)
			} else if election == "3" {
				getListOfFiles()
			} else if election == "4" {
				fmt.Print("Nombre del archivo: ")
				fmt.Scanf("%s\n", &election)
				deleteFileFromURL("https://localhost:10443/delete/?file=" + election)
			} else {
				color.Red("Opción no valida, elige una opción valida")
			}
		}
	}

}

func signin() {
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// # Sing In
	var name string
	var lastname string
	var email string
	fmt.Print("Introduce tu nombre:")
	fmt.Scanf("%s\n", &name)
	fmt.Print("Introduce tus apellidos:")
	fmt.Scanf("%s\n", &lastname)
	fmt.Print("Introduce tu email:")
	fmt.Scanf("%s\n", &email)
	fmt.Print("Introduce tu contraseña: ")
	password, err := gopass.GetPasswdMasked() // Masked

	hashBase64 := encryptPassword(string(password))

	data := url.Values{}
	data.Set("name", name)
	data.Set("lastname", lastname)
	data.Set("email", email)
	data.Set("password", hashBase64)

	r, err := client.PostForm("https://localhost:10443/signin", data) // enviamos por POST
	chk(err)

	fmt.Println("Respuesta:")
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	fmt.Println()
}

func encryptPassword(password string) string {
	h := sha512.Sum512([]byte(password))
	return base64.StdEncoding.EncodeToString(h[:])
}

func postFile(filename string, targetURL string, token string) error {
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	// this step is very important
	fileWriter, err := bodyWriter.CreateFormFile("uploadfile", filename)
	if err != nil {
		color.Red("Error writing to buffer")
		return err
	}

	// el usuario introduce la contraseña de cifrado
	fmt.Print("Introduce tu contraseña para cifrar el archivo: ")
	password, err := gopass.GetPasswdMasked() // Masked
	// hasheo la contraseña de cifrado
	sha256Pass := createHash(string(password))
	// creo el archivo encriptado
	encryptFile(filename, sha256Pass)

	// open file handle
	fh, err := os.Open(filename + ".enc")
	if err != nil {
		color.Red("Error opening file")
		return err
	}
	defer fh.Close()

	//iocopy
	_, err = io.Copy(fileWriter, fh)
	if err != nil {
		color.Red("Error coping the file")
		return err
	}

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	// request
	req, err := http.NewRequest("POST", targetURL, bodyBuf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", token)

	// reponse
	resp, err := client.Do(req)
	if err != nil {
		color.Red("Error posting the file")
		return err
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		color.Red("Error reading body")
		return err
	}
	fmt.Print("Status: ")
	fmt.Println(resp.Status)
	fmt.Print("respBody: ")
	fmt.Println(string(respBody))
	return nil
}

func downloadFromURL(url string) {
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	tokens := strings.Split(url, "/")
	fileName := strings.Split(tokens[len(tokens)-1], "=")[1]
	color.Green("Downloading", url, "to", fileName)

	// TODO: check file existence first with io.IsExist
	output, err := os.Create(fileName + ".enc")
	if err != nil {
		color.Red("Error while creating", fileName, "-", err)
		return
	}
	defer output.Close()

	// request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", token)

	// reponse
	response, err := client.Do(req)
	if err != nil {
		color.Red("Error posting the file: " + err.Error())
		return
	}
	defer response.Body.Close()

	n, err := io.Copy(output, response.Body)
	if err != nil {
		color.Red("Error while downloading", url, "-", err)
		return
	}

	// el usuario introduce la contraseña de cifrado
	fmt.Print("Introduce tu contraseña para descifrar el archivo: ")
	password, err := gopass.GetPasswdMasked() // Masked
	// hasheo la contraseña de cifrado
	sha256Pass := createHash(string(password))
	// creo el archivo desencriptado
	decryptFile(fileName, sha256Pass)
	color.Green(string(n) + " bytes downloaded !")
}

func getListOfFiles() {
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// request
	req, err := http.NewRequest("GET", "https://localhost:10443/listFiles", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", token)

	// reponse
	response, err := client.Do(req)
	if err != nil {
		color.Red("Request error: " + err.Error())
		return
	}
	defer response.Body.Close()

	// leo la información del body
	body, err := ioutil.ReadAll(response.Body)
	chk(err)
	// declaro la lista que recibiré
	var list []FileInfo
	unmarchalErr := json.Unmarshal(body, &list)
	chk(unmarchalErr)
	// imprimo por pantalla la lista
	color.Cyan("------------Lista de tus archivos-------------")
	for i := 0; i < len(list); i++ {
		color.Green("- " + list[i].Name)
	}

}

func deleteFileFromURL(path string) {
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// request
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", token)

	// reponse
	response, err := client.Do(req)
	if err != nil {
		fmt.Println(response.Status)
	}
	defer response.Body.Close()

	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		color.Red("Error reading body")
		return
	}
	color.Green(string(respBody))
}

// crea el hash en sha256
func createHash(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// encrypta un fichero pasandole la ruta del fichero y la contraseña
func encryptFile(file string, sha256Pass string) {
	content, err := cryptoVladernn.ReadFromFile(file)
	if err != nil {
		fmt.Println(err)
		return
	}
	encrypted := cryptoVladernn.Encrypt(string(content), sha256Pass)
	cryptoVladernn.WriteToFile(encrypted, file+".enc")
}

// decrypta un fichero pasandole la ruta y la contraseña
func decryptFile(file string, sha256Pass string) {
	content, err := cryptoVladernn.ReadFromFile(file + ".enc")
	if err != nil {
		fmt.Println(err)
		return
	}
	decrypted := cryptoVladernn.Decrypt(string(content), sha256Pass)
	cryptoVladernn.WriteToFile(decrypted, file)
}

func deleteFile(path string) {
	// delete file
	var err = os.Remove(path)
	chk(err)
}
