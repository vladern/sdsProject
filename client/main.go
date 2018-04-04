package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/howeyc/gopass"
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
	var election string
	var finalizado bool
	finalizado = false
	for !finalizado {
		finalizado = true
		fmt.Println("-----------MENÚ-------------")
		fmt.Println("1.Login")
		fmt.Println("2.Sign In")
		fmt.Print("Que quieres hacer ?:(1 o 2) ")
		fmt.Scanf("%s\n", &election)

		if election == "1" {
			login()
		} else if election == "2" {
			signin()
		} else {
			fmt.Println("Opción no válida, vuelve a intentarlo")
			finalizado = false
		}
	}
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
	fmt.Print("Introduce tu email: ")
	fmt.Scanf("%s\n", &email)
	fmt.Print("Introduce tu contraseña: ")
	password, err := gopass.GetPasswdMasked() // Masked

	// ** ejemplo de registro
	data := url.Values{}                   // estructura para contener los valores
	data.Set("email", email)               // comando (string)
	data.Set("password", string(password)) // usuario (string)

	r, err := client.PostForm("https://localhost:10443/login", data) // enviamos por POST
	chk(err)
	fmt.Println("Respuesta:")
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	fmt.Println()
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

	data := url.Values{}
	data.Set("name", name)
	data.Set("lastname", lastname)
	data.Set("email", email)
	data.Set("password", string(password))

	r, err := client.PostForm("https://localhost:10443/signin", data) // enviamos por POST
	chk(err)
	fmt.Println("Respuesta:")
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	fmt.Println()
}
