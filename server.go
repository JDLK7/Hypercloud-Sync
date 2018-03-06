package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

func connectToDatabase() {
	connectionString := os.Getenv("DB_USERNAME") + ":" + os.Getenv("DB_PASSWORD") +
		"@tcp(" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + ")/" +
		os.Getenv("DB_DATABASE")

	// Conectamos a la Base de Datos y guardamos la conexion en una variable global
	var error error
	db, error = sql.Open("mysql", connectionString)

	if error != nil {
		log.Fatal(error)
	}

}

func getUsers(w http.ResponseWriter, r *http.Request) {

	//Lanzamos una consulta contra la BD para obtener todos los usuarios
	var (
		id    int
		email string
		name  string
	)

	//Guardamos en rows todos los resultados obtenidos
	rows, e := db.Query("select id,email,name from users")

	if e != nil {
		log.Fatal(e)
	}

	defer rows.Close()

	//Recorremos todas las filas y las vamos mostrando
	for rows.Next() {

		//Al pasar los parametros con & se alamacenará el valor de cada columna en ellos

		/*
		   IMPORTANTE A Scan hay que pasarle el mismo numero de parametros que pedimos en la consulta
		   en este caso los 3 campos sino se va a la mierda
		*/
		er := rows.Scan(&id, &email, &name)
		if er != nil {
			log.Fatal(er)
		}
		//log.Println(id, email, name)
	}
	e = rows.Err()
	if e != nil {
		log.Fatal(e)
	}
	w.WriteHeader(http.StatusOK)
	res := make([]byte, 30)
	copy(res[:], strconv.Itoa(id)+" "+email+" "+name)
	fmt.Println(strconv.Itoa(id) + " " + email + " " + name)

	w.Write(res)

}

// Comprueba si el usuario existe en la base de datos
func checkIfUserExists(email string) bool {
	stmtOut, err := db.Prepare("SELECT EXISTS (SELECT * FROM users WHERE email = ?)")
	if err != nil {
		panic(err.Error())
	}
	defer stmtOut.Close()

	var exists bool

	queryError := stmtOut.QueryRow(email).Scan(&exists)
	if queryError != nil && queryError != sql.ErrNoRows {
		panic(queryError)
	}

	return exists
}

func loginUser(w http.ResponseWriter, r *http.Request) {


	var userData map[string]interface{}
	buf := make([]byte, 512)
	n, _ := r.Body.Read(buf)

	if err := json.Unmarshal(buf[:n], &userData); err != nil {
		//panic(err)
		fmt.Println(err)
	}

	stmtIns, err := db.Prepare("SELECT email, password FROM users WHERE email = ? ")
	if err != nil {
		//panic(err.Error())
	}
	defer stmtIns.Close()

	//cipherPass := encryptHashedPassword(hashPassword(userData["password"].(string)))

	var hash, email string

	queryError := stmtIns.QueryRow(userData["email"].(string)).Scan(&email, &hash)
	hashedPass := decryptHashedPassword(hash)
	if queryError != nil {
		//panic(queryError)
	}
	var passIn, _ = base64.StdEncoding.DecodeString(userData["password"].(string))
	if bcrypt.CompareHashAndPassword(hashedPass, passIn) == nil {
		w.Write([]byte("Correct password"))
	} else {
		w.Write([]byte("Wrong user or password"))
	}

}

func registerUser(w http.ResponseWriter, r *http.Request) {

	var userData map[string]interface{}
	buf := make([]byte, 512)
	n, _ := r.Body.Read(buf)

	if err := json.Unmarshal(buf[:n], &userData); err != nil {
		panic(err)
	}

	if !checkIfUserExists(userData["email"].(string)) {

		stmtIns, err := db.Prepare("INSERT INTO users (email, password, name) VALUES (?, ?, ?)")
		if err != nil {
			panic(err.Error())
		}
		defer stmtIns.Close()

		cipherPass := encryptHashedPassword(hashPassword(userData["password"].(string)))

		_, queryError := stmtIns.Exec(userData["email"].(string), cipherPass, userData["name"].(string))
		if queryError != nil {
			panic(queryError)
		}

		w.Write([]byte("Correctly registered user"))
	} else {
		w.Write([]byte("User already exists"))
	}
}

// Devuelve la clave cifrada con la "pimienta" en base64.
func encryptHashedPassword(hash []byte) string {
	// Se decodifica la clave de cifrado que está guardada como variable de entorno.
	key, _ := base64.StdEncoding.DecodeString(os.Getenv("APP_KEY"))

	// Se instancia el cifrador
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// El vector de inicialización debe ser único, pero no seguro. Por lo tanto,
	// es común incluirlo al principio del texto cifrado.
	ciphertext := make([]byte, aes.BlockSize+len(hash))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// Se cifra el hash.
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], hash)

	// Se devuelve codificado en base64 para almacenarlo.
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// Devuelve la clave descifrada como []byte
func decryptHashedPassword(cipherPassword string) []byte {
	// Se decodifica el texto cifrado.
	ciphertext, _ := base64.StdEncoding.DecodeString(cipherPassword)

	// Se decodifica la clave de cifrado que está guardada como variable de entorno.
	key, _ := base64.StdEncoding.DecodeString(os.Getenv("APP_KEY"))

	// Se instancia el cifrador.
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Se recupera el vector de inicialización del texto cifrado.
	iv := ciphertext[:aes.BlockSize]

	// Se crea un slice de bytes para almacenar el texto en claro.
	// Posteriormente se tendrá que acortar con el tamaño del hash generado
	// por la contraseña que se ha enviado al hacer login.
	hash := make([]byte, 255)

	// Se descifra.
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(hash, ciphertext[aes.BlockSize:])

	return hash
}

// Devuelve el hash de la contraseña en []byte
func hashPassword(password string) []byte {
	passwordBytes, _ := base64.StdEncoding.DecodeString(password)

	hashedPassword, err := bcrypt.GenerateFromPassword(passwordBytes, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	return hashedPassword
}

// Compara si la contraseña coincide con el hash
func comparePassword(hashedPassword, plainPassword []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedPassword, plainPassword)
	if err != nil {
		return false
	}

	return true
}

// Funcion que se ejecuta antes que main
func init() {
	// Carga las variables de entorno
	gotenv.Load()
}

func main() {

	connectToDatabase()
	defer db.Close()
	//getUsers()

	r := mux.NewRouter()
	r.HandleFunc("/users", getUsers)
	r.HandleFunc("/register", registerUser)
	r.HandleFunc("/login", loginUser)
	//http.Handle("/", r)
	http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", r)

}