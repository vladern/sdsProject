package authentication

import (
	"crypto/rsa"
	"io/ioutil"
	"log"

	"github.com/sdsProject/server/fileReader"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/sdsProject/server/models"

	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	privateBytes, err := ioutil.ReadFile("./certificates/private.rsa")
	if err != nil {
		log.Fatal("No se pudo leer el archivo privado: " + err.Error())
	}

	publicBytes, err := ioutil.ReadFile("./certificates/public.rsa.pub")
	if err != nil {
		log.Fatal("No se pudo leer el archivo publico: " + err.Error())
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes)
	if err != nil {
		log.Fatal("No se pudo hacer el parse a privatekey: " + err.Error())
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytes)
	if err != nil {
		log.Fatal("No se pudo hacer el parse a privatekey: " + err.Error())
	}
}

func GenerateJWT(user models.User) string {
	claims := models.Claim{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
			Issuer:    "Taller de sábado",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	result, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("No se pudo firmar el token")
	}
	return result
}

func Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	user := models.User{Email: r.Form.Get("email"), Password: r.Form.Get("password")}

	if ValidateUserAndPassword(user) {

		token := GenerateJWT(user)
		result := models.ResponseToken{token}
		jsonResult, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintln(w, "Error al generar el json")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResult)
	} else {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Usario o clave no válidos")
	}
}

// ValidateToken validamos el token que nos llega, si lo hemos emitido nosotros o no
func ValidateToken(w http.ResponseWriter, r *http.Request) {
	token, err := request.ParseFromRequestWithClaims(r, request.OAuth2Extractor, &models.Claim{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError:
			vErr := err.(*jwt.ValidationError)
			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				fmt.Fprintln(w, "Su token ha expirado")
				return
			case jwt.ValidationErrorSignatureInvalid:
				fmt.Fprintln(w, "La firma del token no coincide")
				return
			default:
				fmt.Fprintln(w, "Su token no es válido")
				return
			}
		default:
			fmt.Fprintln(w, "Su token no es válido")
			return
		}
	}

	if token.Valid {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "Bienvenido al sistema")
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Su token no es válido")
	}
}

//ValidateUserAndPassword validamos que el usuario y contraseña que nos han pasado es existe en la bbdd
func ValidateUserAndPassword(user models.User) bool {

	// recupero todos los usuarios de la base de datos
	users := fileReader.GetUsersFromDataBase()
	// recorremos todos los usuarios comprobando que coincidan su email y su contraseña
	for _, element := range users {
		fmt.Println("usuario0: " + element.Email + " password: " + element.Password)
		fmt.Println("usuario1: " + user.Email + " password: " + user.Password)
		if user.Email == element.Email && user.Password == element.Password {
			return true
		}
	}
	return false
}
