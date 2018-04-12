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

// GetUserFromDataBase consigue un usuario dado el email del usuario
func GetUserFromDataBase(email string) (models.User, bool) {
	users := GetUsersFromDataBase()
	for _, user := range users {
		if user.Email == email {
			return user, true
		}
	}
	return models.User{}, false
}

// AddUserToDataBase añade un nuevo usuario a nuestra base de datos
func AddUserToDataBase(user models.User) {
	users := GetUsersFromDataBase()
	users = append(users, user)
	writeInDataBase(users)
}

// UpdateUserIntoDataBase actualiza la información de un usuario dado
func UpdateUserIntoDataBase(user models.User) {
	DeleteUserFromDataBase(user)
	AddUserToDataBase(user)
}

// DeleteUserFromDataBase borra un usuario de la base de datos
func DeleteUserFromDataBase(user models.User) {
	users := GetUsersFromDataBase()
	for i := 0; i < len(users); i++ {
		if users[i].Email == user.Email {
			users = append(users[:i], users[i+1:]...)
			i-- // form the remove item index to start iterate next item
		}
	}
	writeInDataBase(users)
}

// guardo los datos de los usuarios en la bbdd
func writeInDataBase(users []models.User) {
	// transformo el array en json
	b, err := json.Marshal(users)
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
