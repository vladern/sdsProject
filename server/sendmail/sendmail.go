package sendmail

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/mail"
	"net/smtp"
)

type SHA256 struct {
	Token string
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Se produjo un error: " + err.Error())
	}
}

// SendMail recibe el nombre y el mail del destinatario ademas del token de verificación
// y envia el correo al destinatario para comprobar que el correo existe
func SendMail(name string, toMail string, token string, templateURL string) (err error) {

	var devolver error

	fmt.Println("Peta")
	fmt.Println(name + " " + toMail + " " + token + " " + templateURL)

	// en el futuro habrá que meter esto en variables de entorno o algo así
	from := mail.Address{"Vladyslav Kuchmenko", "vladernn@gmail.com"}
	to := mail.Address{name, toMail}
	subject := "Confirmación correo sistema backup seguro en GO"

	dest := SHA256{Token: token}

	headers := make(map[string]string)
	headers["From"] = from.String()
	headers["To"] = to.String()
	headers["Subject"] = subject
	headers["Content-Type"] = `text/html; charset="UTF-8"`

	mensaje := ""

	for k, v := range headers {
		mensaje += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	t, err := template.ParseFiles(templateURL)
	devolver = err
	checkError(err)

	buf := new(bytes.Buffer)
	err = t.Execute(buf, dest)
	devolver = err
	checkError(err)

	mensaje += buf.String()

	servername := "smtp.gmail.com:465"
	host := "smtp.gmail.com"

	// TODO: refactorizar para que el correo y la contraseña se encuentren en un archivo aparte,
	// dicho archivo se sifrará cada vez que el servidor se apague
	auth := smtp.PlainAuth("", "vladernn@gmail.com", "3MiHashSHA256SuperSecreto3", host)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	conn, err := tls.Dial("tcp", servername, tlsConfig)
	devolver = err
	checkError(err)

	client, err := smtp.NewClient(conn, host)
	devolver = err
	checkError(err)

	err = client.Auth(auth)
	devolver = err
	checkError(err)

	err = client.Mail(from.Address)
	devolver = err
	checkError(err)

	err = client.Rcpt(to.Address)
	devolver = err
	checkError(err)

	w, err := client.Data()
	devolver = err
	checkError(err)

	_, err = w.Write([]byte(mensaje))
	devolver = err
	checkError(err)

	err = w.Close()
	devolver = err
	checkError(err)

	client.Quit()

	return devolver
}
