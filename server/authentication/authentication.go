package authentication

import (
	"crypto/rsa"
	"crypto/sha512"
	"io/ioutil"
	"log"
	"os"

	"github.com/sdsProject/server/fileReader"
	"github.com/sdsProject/server/salt"
	"github.com/sdsProject/server/sendmail"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/sdsProject/server/models"

	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	otpKey     map[string]models.Otp
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

	otpKey = make(map[string]models.Otp)

	file, _ := os.OpenFile("./logs/logrus.log", os.O_CREATE|os.O_WRONLY, 0666)

	log.SetOutput(file)

}

// GenerateJWT genera un token jwt
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

	email := r.Form.Get("email")
	// recogemos los datos mandados por el cliente
	user := models.User{Email: email, Password: r.Form.Get("password")}

	// validamos que el usuario y el password coincidan con los de la base de datos
	if ValidateUserAndPassword(user) {
		// genero la key de otp y le asigno el tiempo máximo de duración en segundos
		key := models.GenerateOTP()

		// añado la key a en memoria
		otpKey[email] = key
		// obtengo el usuario
		user, Ok := fileReader.GetUserFromDataBase(email)
		if !Ok {
			w.WriteHeader(http.StatusForbidden)
			log.Fatal("Usuario no encontrado: " + email)
			fmt.Fprintln(w, "Algo ha ido mal, vuelve a intentarlo")
		}
		// envio el email de doble autentificación al usuario
		error := sendmail.SendMail(user.Name, user.Email, key.Pin, "./templates/doubleAuth.html")
		if error != nil {
			w.WriteHeader(http.StatusForbidden)
			log.Fatal("Usuario o clave no válidos: " + email)
			fmt.Fprintln(w, "Usario o clave no válidos")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Revisa tu correo electrónico para validar el pin de verificación"))
	} else {
		w.WriteHeader(http.StatusForbidden)
		log.Fatal("Usuario o clave no válidos: " + email)
		fmt.Fprintln(w, "Usario o clave no válidos")
	}
}

// ValidateOTPKey valida el pin del doble factor de autentificación
func ValidateOTPKey(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var key models.Otp
	email := r.Form.Get("email")
	// recogemos los datos mandados por el cliente
	key = otpKey[email]
	passcode := r.Form.Get("pin")
	fmt.Println(passcode)
	// valido el pin
	valid := models.ValidateOTP(passcode, key, 200)
	if !valid {
		w.WriteHeader(http.StatusForbidden)
		log.Fatal("El pin es incorrecto: " + email)
		fmt.Fprintln(w, "El pin es incorecto")
	} else {
		user, ok := fileReader.GetUserFromDataBase(email)
		if !ok {
			log.Fatal("No se ha podido obtener el usuario de la bbdd: " + email)
			fmt.Fprintln(w, "No se ha podido obtener el usuario de la bbdd")
		} else {
			// borro el otpKey del diccionario
			delete(otpKey, email)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(GenerateJWT(user)))
			log.Println("Se ha validado el OTPKey: " + email)
		}

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
		err := sendmail.SendMail(user.Name, user.Email, token, "./sendmail/template.html")
		// si no se produce ningún error a la hora de enviar el correo se añade el usuario
		if err == nil {
			// genero la sal y hasheo el password junto con la sal
			user.Sal = salt.RandStringBytesMask(20)
			user.Password = encryptPassword(user.Password + user.Sal)
			// se añade el usuario a la base de datos
			fileReader.AddUserToDataBase(user)
			log.Println("Usuario Registrado: " + user.Email)
		}

	} else {
		w.WriteHeader(http.StatusForbidden)
		log.Fatal("Format exception, el formato no es adecuado o faltan datos:" + user.Email)
		fmt.Fprintln(w, "Format exception, el formato no es adecuado o faltan datos")
	}
}

// ValidateEmail validamos el token del email
func ValidateEmail(w http.ResponseWriter, r *http.Request) {

	token, _ := r.URL.Query()["token"]
	claims, ok := ExtractClaims(token[0])

	if ok {
		userToUpload, userExist := fileReader.GetUserFromDataBase(claims.User.Email)
		userToUpload.Role = "validated user"
		if userExist {
			fileReader.UpdateUserIntoDataBase(userToUpload)
			w.WriteHeader(http.StatusAccepted)
			log.Println("Email verificado: " + claims.Email)
		}
		// devuelve una página web
		body, err := ioutil.ReadFile("templates/validateEmailOk.html")
		if err != nil {
			log.Fatal("Error al leer el template" + err.Error())
		}
		fmt.Fprint(w, string(body))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		log.Fatal("Su token no es válido")
		// devuelve una pagina web
		body, err := ioutil.ReadFile("templates/validateEmailFail.html")
		if err != nil {
			log.Fatal("Error al leer el template: " + claims.Email + " : Error: " + err.Error())
		}
		log.Println("Email validado: " + claims.Email)
		fmt.Fprint(w, string(body))
	}
}

//ValidateUserAndPassword validamos que el usuario y contraseña que nos han pasado es existente y valida en la bbdd
func ValidateUserAndPassword(user models.User) bool {

	// recupero al usuario con email que me han pasado pero de base de datos
	userFromDB, ok := fileReader.GetUserFromDataBase(user.Email)
	// compruebo que dicho usuario existe en la base de datos
	if ok {
		// compruebo que las contraseñas conincidan en la base de datos
		if userFromDB.Password == encryptPassword(user.Password+userFromDB.Sal) {
			log.Println("Constraseña valida: " + user.Email)
			return true
		} else {
			log.Fatal("Constraseña no valida: " + user.Email)
			return false
		}
	} else {
		log.Fatal("Usuario no existe: " + user.Email)
		return false
	}

}

// ExtractClaims devuelve las Claims del token y si dicho token es valido o no
func ExtractClaims(tokenStr string) (*models.Claim, bool) {

	token, err := jwt.ParseWithClaims(tokenStr, &models.Claim{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if err != nil {
		log.Print("Error parsing tokenStr:" + err.Error())
		return &models.Claim{}, false
	}

	claims, ok := token.Claims.(*models.Claim)
	if ok && token.Valid {
		log.Println("Token is valid: " + claims.Email)
		return claims, true
	} else {
		log.Printf("Invalid JWT Token")
		return &models.Claim{}, false
	}
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	if err != nil {
		log.Panic(err)
	}
	return b // devolvemos los datos originales
}

func encryptPassword(password string) string {
	h := sha512.Sum512([]byte(password))
	return base64.StdEncoding.EncodeToString(h[:])
}
