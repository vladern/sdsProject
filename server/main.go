package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/sdsProject/server/authentication"
	"github.com/sdsProject/server/fileManagement"
)

func main() {
	fmt.Println("Corriendo el servidor")
	server()
}

func chk(e error) {
	if e != nil {
		panic(e)
	}
}

/***
SERVIDOR
***/
// gestiona el modo servidor
func server() {
	// suscripción SIGINT
	stopChan := make(chan os.Signal)
	signal.Notify(stopChan, os.Interrupt)

	mux := http.NewServeMux()
	// Rutas
	mux.Handle("/login", http.HandlerFunc(authentication.Login))
	mux.Handle("/signin", http.HandlerFunc(authentication.Signin))
	mux.Handle("/verificarMail/", http.HandlerFunc(authentication.ValidateEmail))
	mux.Handle("/verficarPin", http.HandlerFunc(authentication.ValidateOTPKey))
	mux.Handle("/upload", http.HandlerFunc(fileManagement.Upload))
	mux.Handle("/download/", http.HandlerFunc(fileManagement.Download))
	mux.Handle("/listFiles", http.HandlerFunc(fileManagement.ListFiles))
	mux.Handle("/delete/", http.HandlerFunc(fileManagement.DeleteFile))

	srv := &http.Server{Addr: ":10443", Handler: mux}

	go func() {
		if err := srv.ListenAndServeTLS("./certificates/server.crt", "./certificates/server.key"); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()

	<-stopChan // espera señal SIGINT
	log.Println("Apagando servidor ...")

	// apagar servidor de forma segura
	ctx, fnc := context.WithTimeout(context.Background(), 5*time.Second)
	fnc()
	srv.Shutdown(ctx)

	log.Println("Servidor detenido correctamente")
}
