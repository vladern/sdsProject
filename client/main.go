package main

import (
	"crypto/tls"
	"log"
)

func main() {
	log.SetFlags(log.Lshortfile)

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", "127.0.0.1:443", conf)

	if err != nil {
		log.Println("Fallo en el Dial")
		log.Println(err)
	}

	defer conn.Close()

	n, err := conn.Write([]byte("Hola servidor\n"))

	if err != nil {
		log.Println("Fallo en el Write")
		log.Println(err)
	}

	buf := make([]byte, 100)
	n, err = conn.Read(buf)

	if err != nil {
		log.Println(n, err)
		return
	}

	println(string(buf[:n]))
}
