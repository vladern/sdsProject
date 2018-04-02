package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	client()
}

/***
CLIENTE
***/

// gestiona el modo cliente
func client() {

	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// # Login
	var email string
	var password string
	fmt.Print("Introduce tu email: ")
	fmt.Scanf("%s\n", &email)
	fmt.Print("Introduce tu contraseña: ")
	fmt.Scanf("%s\n", &password)

	// ** ejemplo de registro
	data := url.Values{}           // estructura para contener los valores
	data.Set("email", email)       // comando (string)
	data.Set("password", password) // usuario (string)

	r, err := client.PostForm("https://localhost:10443/login", data) // enviamos por POST
	chk(err)
	fmt.Println("Respuesta:")
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	fmt.Println()
}
