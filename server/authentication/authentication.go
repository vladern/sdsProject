package authentication

import (
	"crypto/rsa"
	"io/ioutil"
	"log"

	"github.com/sdsProject/server/fileReader"
	"github.com/sdsProject/server/sendmail"

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
		User: models.User{Email: user.Email},
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
			Issuer:    "BackUPSecure",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	result, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("No se pudo firmar el token")
	}
	return result
}

// Login se valida que el usuario existe en nuestro sistema
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

// Signin se registra un nuevo usuario en el sistema
func Signin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// parseamos todos los datos recibidos
	user := models.User{Name: r.Form.Get("name"), Lastname: r.Form.Get("lastname"), Email: r.Form.Get("email"), Password: r.Form.Get("password")}
	user.Role = "not validated user"
	if user.Name != "" && user.Lastname != "" && user.Email != "" && user.Password != "" {

		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("Content-Type", "text")
		fmt.Fprintln(w, "Ok, revisa tú correo electrónico para validar la cuenta")
		// genero el token
		token := GenerateJWT(user)
		// envio el correo
		err := sendmail.SendMail(user.Name, user.Email, token)
		// si no se produce ningún error a la hora de enviar el correo se añade el usuario
		if err == nil {
			// se añade el usuario a la base de datos
			fileReader.AddUserToDataBase(user)
		}

	} else {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Format exception, el formato no es adecuado o faltan datos")
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

// ValidateEmail validamos el token del email
func ValidateEmail(w http.ResponseWriter, r *http.Request) {

	token, _ := r.URL.Query()["token"]
	claims, ok := extractClaims(token[0])

	if ok {
		userToUpload, userExist := fileReader.GetUserFromDataBase(claims.User.Email)
		userToUpload.Role = "validated user"
		if userExist {
			fileReader.UpdateUserIntoDataBase(userToUpload)
			w.WriteHeader(http.StatusAccepted)
		}
		// devuelve una página web
		body, err := ioutil.ReadFile("templates/validateEmailOk.html")
		if err != nil {
			fmt.Println("Error al leer el template" + err.Error())
		}
		fmt.Fprint(w, string(body))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println("Su token no es válido")
		// devuelve una pagina web
		body, err := ioutil.ReadFile("templates/validateEmailFail.html")
		if err != nil {
			fmt.Println("Error al leer el template" + err.Error())
		}
		fmt.Fprint(w, string(body))
	}
}

//ValidateUserAndPassword validamos que el usuario y contraseña que nos han pasado es existe en la bbdd
func ValidateUserAndPassword(user models.User) bool {

	// recupero todos los usuarios de la base de datos
	users := fileReader.GetUsersFromDataBase()
	// recorremos todos los usuarios comprobando que coincidan su email y su contraseña
	for _, element := range users {
		if user.Email == element.Email && user.Password == element.Password {
			return true
		}
	}
	return false
}

func extractClaims(tokenStr string) (*models.Claim, bool) {

	token, err := jwt.ParseWithClaims(tokenStr, &models.Claim{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if err != nil {
		log.Print("Error parsing tokenStr:" + err.Error())
		return &models.Claim{}, false
	}

	claims, ok := token.Claims.(*models.Claim)
	if ok && token.Valid {
		return claims, true
	} else {
		log.Printf("Invalid JWT Token")
		return &models.Claim{}, false
	}
}
