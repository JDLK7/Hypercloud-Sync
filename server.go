package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"github.com/gorilla/mux"
	_ "github.com/go-sql-driver/mysql"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strconv"
	"fmt"
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
	copy(res[:], strconv.Itoa(id) + " " + email + " " + name)
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
		panic(err)
	}

	stmtIns, err := db.Prepare("SELECT email, password FROM users WHERE email = ? " )
	if err != nil {
		panic(err.Error())
	}
	defer stmtIns.Close()

	cipherPass := encryptHashedPassword(hashPassword(userData["password"].(string)))

	var hash, email string

	queryError := stmtIns.QueryRow(userData["email"].(string)).Scan(&email, &hash)

	if queryError != nil {
		panic(queryError)
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(userData["password"].(string))) == nil {
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

// Devuelve la clave cifrada con la "pimienta" en base64
func encryptHashedPassword(hash []byte) string {
	key, _ := base64.StdEncoding.DecodeString(os.Getenv("APP_KEY"))

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, hash, nil)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

// Devuelve la clave cifrada con la "pimienta" en base64
func decryptHashedPassword(hash []byte) string {
	key, _ := base64.StdEncoding.DecodeString(os.Getenv("APP_KEY"))

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, hash, nil)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

// Devuelve el hash de la contraseña en []byte
func hashPassword(password string) []byte {
	passwordBytes := []byte(password)

	hashedPassword, err := bcrypt.GenerateFromPassword(passwordBytes, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	return hashedPassword
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
	http.ListenAndServeTLS("0.0.0.0:8443", "cert.pem", "key.pem", r)

}

func loadCertificates(){
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	service := "0.0.0.0:8443"
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			log.Print("ok=true")
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		go handleClient(conn)
	}
}


func handleClient(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		log.Print("server: conn: waiting")
		n, err := conn.Read(buf)
		if err != nil {
			if err != nil {
				log.Printf("server: conn: read: %s", err)
			}
			break
		}
		log.Printf("server: conn: echo %q\n", string(buf[:n]))

		var request map[string]interface{}

		if err := json.Unmarshal(buf[:n], &request); err != nil {
			panic(err)
		}



		n, err = conn.Write(buf[:n])

		n, err = conn.Write(buf[:n])
		log.Printf("server: conn: wrote %d bytes", n)

		if err != nil {
			log.Printf("server: write: %s", err)
			break
		}
	}
	log.Println("server: conn: closed")
}
