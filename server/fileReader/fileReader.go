package fileReader

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/sdsProject/server/models"
)

// GetUsersFromDataBase devuelve un string con toda la BBDD de usuarios
func GetUsersFromDataBase() []models.User {
	// leo el archivo entero de usuarios
	f, err := ioutil.ReadFile("./bbdd/bbdd.txt")
	if err != nil {
		log.Fatal("No se ha podido habrir el archivo de BBDD" + err.Error())
	}
	// declaro la variable users
	var users []models.User
	// paso los usuarios del JSON a objetos
	json.Unmarshal(f, &users)
	// devuelvo los usuarios obtenidos
	return users
}

// AddUserToDataBase añade un nuevo usuario a nuestra base de datos
func AddUserToDataBase(user models.User) {
	users := GetUsersFromDataBase()
	users = append(users, user)
	fmt.Println(users)
	// transformo el array en json
	b, err := json.Marshal(users)
	fmt.Println(string(b))
	if err != nil {
		fmt.Printf("Error: %s", err)
		return
	}

	f, error := os.Create("./bbdd/bbdd.txt")
	if error != nil {
		log.Fatal("Error a la hora de crear el fichero de bbdd.txt")
	}
	// escribo en el fichero
	fmt.Fprint(f, string(b))
	// cierro el stream
	f.Close()
}
