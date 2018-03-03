package main

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
)

func main() {

	// leo el certificado autogenerado
	cer, err := tls.LoadX509KeyPair("./certificates/server.crt", "./certificates/server.key")
	// muestro el log en el caso de que se produsca error
	if err != nil {
		log.Println("Error en el LoadX509KeyPair")
		log.Println(err)
		return
	}

	// se construye la configuración a partir del certificado anterior
	config := &tls.Config{Certificates: []tls.Certificate{cer}}

	// escucho peticiones por el puerto 433
	ln, err := tls.Listen("tcp", ":443", config)
	// muestro el log en el caso de que se produsca error
	if err != nil {
		log.Println("Error en el Listen")
		log.Println(err)
	}
	// se aplaza el cierre de la linea hasta que acabe la func
	defer ln.Close()

	for {
		// se acepta la conexión
		conn, err := ln.Accept()
		// muestro log en el caso de que se produsca error
		if err != nil {
			log.Println("Error en el Accept")
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	// se aplaza el cierre de la conexión hasta que acabe la func
	defer conn.Close()
	// se abre el buffer reader
	r := bufio.NewReader(conn)
	// se lee el mensaje
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			log.Println("Error en el ReadString")
			log.Println(err)
		}
		// se imprime el mensaje
		println(msg)

		// se contesta al mensaje
		n, err := conn.Write([]byte("Hola cliente\n"))
		if err != nil {
			log.Println("Error en el Write")
			log.Println(n, err)
			return
		}
	}
}
