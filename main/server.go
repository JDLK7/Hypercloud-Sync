package main

import (
	"Hypercloud-Sync/types"
	"Hypercloud-Sync/utils"
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
	"path/filepath"
	"strconv"

	_ "github.com/go-sql-driver/mysql"

	//"github.com/gorilla/mux"
	"net/smtp"

	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
	//"github.com/gorilla/mux"
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"io/ioutil"
)

type verifyResponse struct {
	Ok      bool   `json:"ok"`
	Message string `json:"message"`
	Jwt     string `json:"jwt"`
}

var db *sql.DB

func connectToDatabase() {
	log.Println("Intentando abrir conexión con el servidor de base de datos...")

	connectionString := os.Getenv("DB_USERNAME") + ":" + os.Getenv("DB_PASSWORD") +
		"@tcp(" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + ")/" +
		os.Getenv("DB_DATABASE")

	// Conectamos a la Base de Datos y guardamos la conexion en una variable global
	var err error
	db, err = sql.Open("mysql", connectionString)

	if err != nil {
		log.Panicln("Error al conectar con el servidor de base de datos")
		log.Panicln(err.Error())
	} else {
		log.Println("Conexión con el servidor de base de datos satisfactoria")
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
	rows, e := db.Query("SELECT id, email, name FROM users")
	if e != nil {
		log.Panicln("Error al obtener los usuarios de la BD:")
		log.Fatal(e.Error())
	}

	defer rows.Close()

	//Recorremos todas las filas y las vamos mostrando
	for rows.Next() {

		//Al pasar los parametros con & se alamacenará el valor de cada columna en ellos
		er := rows.Scan(&id, &email, &name)
		if er != nil {
			log.Panicln("Error al instanciar los datos de los usuarios")
			log.Fatal(er.Error())
		}
	}

	e = rows.Err()
	if e != nil {
		log.Fatal(e)
	}

	w.WriteHeader(http.StatusOK)
	res := make([]byte, 30)
	copy(res[:], strconv.Itoa(id)+" "+email+" "+name)

	w.Write(res)

}

// Comprueba si el usuario existe en la base de datos
func checkIfUserExists(email string) bool {
	stmtOut, err := db.Prepare("SELECT EXISTS (SELECT * FROM users WHERE email = ?)")
	if err != nil {
		log.Panicln("Error de sintaxis al comprobar si un usuario está registrado en la BD:")
		log.Fatal(err.Error())
	}
	defer stmtOut.Close()

	var exists bool

	queryError := stmtOut.QueryRow(email).Scan(&exists)
	if queryError != nil && queryError != sql.ErrNoRows {
		log.Panicln("Error al comprobar si un usuario existe:")
		log.Panic(queryError.Error())
	}

	return exists
}

func getUserId(email string) int {
	stmtOut, err := db.Prepare("SELECT id FROM users WHERE email = ?")
	if err != nil {
		log.Panicln("Error de sintaxis al comprobar si un usuario está registrado en la BD:")
		log.Fatal(err.Error())
	}
	defer stmtOut.Close()

	var id int

	queryError := stmtOut.QueryRow(email).Scan(&id)
	if queryError != nil && queryError != sql.ErrNoRows {
		log.Panicln("Error al comprobar si un usuario existe:")
		log.Panic(queryError.Error())
	}

	return id
}

func loginUser(w http.ResponseWriter, r *http.Request) {

	var userData map[string]interface{}
	buf := make([]byte, 512)
	n, _ := r.Body.Read(buf)

	if err := json.Unmarshal(buf[:n], &userData); err != nil {
		log.Panicln("Error al parsear datos en JSON de login:")
		log.Panic(err.Error())
	}

	stmtIns, err := db.Prepare("SELECT email, password FROM users WHERE email = ? ")
	if err != nil {
		log.Panicln("Error de sintaxis al comprobar datos de login en la BD:")
		log.Fatal(err.Error())
	}
	defer stmtIns.Close()

	var hash, email string

	queryError := stmtIns.QueryRow(userData["email"].(string)).Scan(&email, &hash)
	if queryError != nil {
		log.Printf("El usuario '%s' ha intentado iniciar sesión sin estar registrado\n", userData["email"])
		return
	}

	hashedPass := decryptHashedPassword(hash)

	var passIn, _ = base64.StdEncoding.DecodeString(userData["password"].(string))
	if bcrypt.CompareHashAndPassword(hashedPass, passIn) == nil {
		codigo := generateCode(email)
		sendMail(email, "Codigo: H-"+string(codigo), "\nIntroduce el siguiente codigo en la aplicación para continuar: H-"+strconv.Itoa(codigo)+"\nEste codigo solo tiene validez durante 1 hora")
		w.Write([]byte("Se te ha un código de acceso a tu email, por favor comprueba tu bandeja de entrada"))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Usuario o contraseña incorrecta"))
	}

}

func verifyCode(w http.ResponseWriter, r *http.Request) {

	var verifyData map[string]interface{}
	buf := make([]byte, 512)
	n, _ := r.Body.Read(buf)

	if err := json.Unmarshal(buf[:n], &verifyData); err != nil {
		log.Panicln("Error al parsear datos en JSON de código de verificación:")
		log.Panic(err.Error())
	}

	stmtIns, err := db.Prepare("SELECT loginCod, timeValid FROM users WHERE email = ?")
	if err != nil {
		log.Panicln("Error al comprobar el código de verificación en la BD:")
		log.Panic(err.Error())
	}
	defer stmtIns.Close()

	var loginCode, timeValid string

	queryError := stmtIns.QueryRow(verifyData["email"].(string)).Scan(&loginCode, &timeValid)
	if queryError != nil {
		log.Printf("El usuario '%s' ha introducido un código de verificación no válido\n", verifyData["email"])
	}

	timeParsed, _ := strconv.ParseInt(timeValid, 10, 64)

	var verifyDataResponse verifyResponse

	if loginCode == verifyData["code"] && utils.CheckTime(time.Now(), time.Unix(timeParsed, 0)) {

		verifyDataResponse = verifyResponse{
			Ok:      true,
			Message: "Código de verificación correcto",
			Jwt:     generateToken(verifyData["email"].(string)),
		}

	} else {
		verifyDataResponse = verifyResponse{
			Ok:      false,
			Message: "Código de verificación erróneo",
		}
	}

	data, _ := json.Marshal(verifyDataResponse)

	w.Write([]byte(data))

}

func generateToken(user string) string {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, _ := token.SignedString([]byte(os.Getenv("APP_KEY")))
	return tokenString
}

func registerUser(w http.ResponseWriter, r *http.Request) {

	var userData map[string]interface{}
	buf := make([]byte, 512)
	n, _ := r.Body.Read(buf)

	if err := json.Unmarshal(buf[:n], &userData); err != nil {
		log.Panicln("Error al parsear datos en JSON de registro:")
		log.Panic(err.Error())
	}

	if !checkIfUserExists(userData["email"].(string)) {

		stmtIns, err := db.Prepare("INSERT INTO users (email, password, name) VALUES (?, ?, ?)")
		if err != nil {
			log.Panicln("Error registrar un usuario en la BD:")
			log.Fatal(err.Error())
		}
		defer stmtIns.Close()

		cipherPass := encryptHashedPassword(hashPassword(userData["password"].(string)))

		_, queryError := stmtIns.Exec(userData["email"].(string), cipherPass, userData["name"].(string))
		if queryError != nil {
			log.Panicf("Error al registrar el usuario '%s' en la BD:\n", userData["email"])
			log.Panic(queryError.Error())
		}

		w.Write([]byte("Usuario registrado correctamente"))
	} else {
		w.Write([]byte("El usuario ya existe"))
	}
}

func getFiles(w http.ResponseWriter, r *http.Request) {

	header := r.Header.Get("Authorization")
	id := getUserByToken(header)
	stmtIns, err := db.Prepare(`
		SELECT f1.id, f1.path, f1.size, f1.updated_at
		FROM files as f1 
		LEFT JOIN files as f2 
		ON (f1.path = f2.path AND f1.updated_at < f2.updated_at) 
		WHERE f1.user_id = ?
		AND f2.id IS NULL;
	`)
	if err != nil {
		log.Panicln("Error de sintaxis al recuperar el listado de ficheros del usuario:")
		log.Fatal(err.Error())
	}
	defer stmtIns.Close()

	//cipherPass := encryptHashedPassword(hashPassword(userData["password"].(string)))

	var idFile string
	var path string
	var size int64
	var updatedAt string

	rows, queryError := stmtIns.Query(id)

	if queryError != nil {
		log.Panicln("Error al recuperar el listado de ficheros del usuario:")
		log.Panic(queryError.Error())
	}

	var files = make([]types.File, 0)

	for rows.Next() {
		rows.Scan(&idFile, &path, &size, &updatedAt)

		var file = types.File{
			Id:   idFile,
			Name: path,
			Size: size,
		}

		files = append(files, file)

	}

	var fileListResponse = types.FilesResponse{
		Ok:    true,
		Files: files,
	}

	data, _ := json.Marshal(fileListResponse)

	w.Write([]byte(data))

}

func getVersions(w http.ResponseWriter, r *http.Request) {

	header := r.Header.Get("Authorization")
	fileID := r.URL.Query().Get("file")
	userID := getUserByToken(header)

	stmtIns, err := db.Prepare(`
		SELECT id, path, size, updated_at
		FROM files as f
		JOIN versions as v ON f.id = v.version_id
		WHERE v.file_id = (
			SELECT file_id
			FROM versions
			WHERE version_id = ?
		)
		AND f.user_id = ?
		ORDER BY updated_at DESC
	`)
	if err != nil {
		log.Panicln("Error de sintaxis al recuperar el listado de versiones de un fichero del usuario:")
		log.Fatal(err.Error())
	}

	defer stmtIns.Close()

	rows, queryError := stmtIns.Query(fileID, userID)
	if queryError != nil {
		log.Panicln("Error al recuperar el listado de versiones de un fichero del usuario:")
		log.Panic(queryError.Error())
	}

	var files = make([]types.File, 0)

	var idFile string
	var path string
	var size int64
	var updatedAt string

	for rows.Next() {
		rows.Scan(&idFile, &path, &size, &updatedAt)

		var file = types.File {
			Id:   idFile,
			Name: path,
			Size: size,
			Date: updatedAt,
		}

		files = append(files, file)
	}

	var fileListResponse = types.FilesResponse{
		Ok:    true,
		Files: files,
	}

	data, _ := json.Marshal(fileListResponse)

	w.Write([]byte(data))
}

// Devuelve la clave cifrada con la "pimienta" en base64.
func encryptHashedPassword(hash []byte) string {
	// Se decodifica la clave de cifrado que está guardada como variable de entorno.
	key, _ := base64.StdEncoding.DecodeString(os.Getenv("APP_KEY"))


	// Se instancia el cifrador
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panicln("Error al instanciar el cifrador AES:")
		log.Panic(err)
	}

	// El vector de inicialización debe ser único, pero no seguro. Por lo tanto,
	// es común incluirlo al principio del texto cifrado.
	ciphertext := make([]byte, aes.BlockSize+len(hash))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Panicln("Error al inicializar el vector de inicialización:")
		log.Panic(err)
	}

	// Se cifra el hash.
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], hash)

	// Se devuelve codificado en base64 para almacenarlo.
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func createVersion(id string, path string, size int64, userID int) {
	stmtIns, err := db.Prepare(`
		SELECT id, updated_at
		FROM files 
		WHERE path = ?
		AND user_id = ?
		GROUP BY path
		ORDER BY updated_at ASC
	`)
	if err != nil {
		log.Panicln("Error de sintaxis al crear una versión de un fichero existente:")
		log.Fatal(err.Error())
	}
	defer stmtIns.Close()

	rows, queryError := stmtIns.Query(path, userID)
	if queryError != nil {
		panic(queryError)
	}

	var originalID string
	var updatedAt string

	for rows.Next() {
		rows.Scan(&originalID, &updatedAt)
		
		stmtIns, err = db.Prepare("INSERT INTO versions (file_id, version_id) VALUES (?, ?)")
		if err != nil {
			log.Panicln("Error de sintaxis al obtener el fichero original de una versión nueva:")
			log.Fatal(err.Error())
		}

		_, queryError := stmtIns.Exec(originalID, id)
		if queryError != nil {
			log.Panicln("Error al obtener el archivo original de una versión nueva:")
			log.Panic(queryError.Error())
		}
	}
}

func upload(w http.ResponseWriter, r *http.Request) {

	os.Mkdir("files", 0755)

	filename := r.Header.Get("X-Filename")
	header := r.Header.Get("Authorization")
	id, _ := uuid.NewUUID()
	file, err := os.Create("files/" + id.String())
	if err != nil {
		log.Panicln("Error al crear el fichero de destino de la subida:")
		log.Panic(err)
	}
	n, err := io.Copy(file, r.Body)
	if err != nil {
		log.Panicln("Error al copiar el contenido de la subida en el fichero de destino:")
		log.Panic(err)
	}

	stmtIns, err := db.Prepare("INSERT INTO files (id, path, size, user_id) VALUES (?, ?, ?, ?)")
	if err != nil {
		log.Panicln("Error de sintaxis al subir un fichero nuevo:")
		log.Fatal(err.Error())
	}
	defer stmtIns.Close()

	_, queryError := stmtIns.Exec(id, filepath.Base(filename), n, getUserByToken(header))
	if queryError != nil {
		log.Panicln("Error al registrar el fichero subido en la BD:")
		log.Panic(queryError.Error())
	}

	createVersion(id.String(), filepath.Base(filename), n, getUserByToken(header))

	w.Write([]byte(fmt.Sprintf("%d bytes are recieved.\n", n)))

}

func downloadFile(w http.ResponseWriter, r *http.Request) {

	var downloadData types.FileDownloadRequest

	buf := make([]byte, 512)
	n, _ := r.Body.Read(buf)

	if err := json.Unmarshal(buf[:n], &downloadData); err != nil {
		log.Panicln("Error al parsear datos en JSON de descarga:")
		log.Panic(err)
	}

	filename := "files/" + downloadData.Id

	file, err := os.Open(filename) // For read access.
	if err != nil {
		log.Fatal(err)
	}
	fi, err := file.Stat()
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	stmtOut, err := db.Prepare("SELECT path FROM files WHERE id = ?")
	if err != nil {
		log.Panicln("Error de sintaxis al descargar un fichero existente:")
		log.Fatal(err.Error())
	}
	defer stmtOut.Close()

	var name string

	queryError := stmtOut.QueryRow(downloadData.Id).Scan(&name)
	if queryError != nil && queryError != sql.ErrNoRows {
		log.Panicln("Error al descargar un fichero registrado en la BD:")
		log.Panic(queryError.Error())
	}

	w.Header().Set("X-Filename", name)
	sizeStr := strconv.FormatInt(fi.Size(), 10)
	w.Header().Set("X-Size", sizeStr)
	w.Write(data)
}

func getUserByToken(header string) int {

	tokens := strings.Split(header, " ")

	if tokens[0] == "Bearer" {

		token, _ := jwt.Parse(tokens[1], func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("APP_KEY")), nil
		})
		if token.Valid && checkIfUserExists(token.Claims.(jwt.MapClaims)["user"].(string)) {
			return getUserId(token.Claims.(jwt.MapClaims)["user"].(string))

		} else {
			fmt.Println("Token no válido")
		}

	} else {
		fmt.Println("La autenticación no es mediante JWT")
	}

	return -1

}

func deleteFile(w http.ResponseWriter, r *http.Request) {

	var deleteData types.FileDeleteRequest
	var originalFileID string
	buf := make([]byte, 512)
	n, _ := r.Body.Read(buf)

	if err := json.Unmarshal(buf[:n], &deleteData); err != nil {
		log.Panicln("Error al parsear datos en JSON de descarga:")
		log.Panic(err)
	}

	stmtOut, err := db.Prepare(`SELECT file_id
		FROM versions
		WHERE version_id = ?`)

	if err != nil {
		log.Panicln("Error de sintaxis al obtener el id del fichero original:")
		log.Fatal(err.Error())
	}

	queryError := stmtOut.QueryRow(deleteData.Id).Scan(&originalFileID)
	if queryError != nil {
		log.Panicln("Error al al obtener el id del fichero original de la BD:")
		log.Panic(err.Error())
	}

	stmtOut, err = db.Prepare(`
		SELECT version_id
		FROM versions 
		WHERE file_id = ?
	`)
	defer stmtOut.Close()
	if err != nil {
		log.Panicln("Error de sintaxis al seleccionar las versiones de un fichero:")
		log.Fatal(err.Error())
	}
	rows, queryError := stmtOut.Query(originalFileID)
	if queryError != nil {
		log.Panicln("Error al seleccionar las versiones de un fichero de la BD:")
		log.Panic(err.Error())
	}

	var idFile string

	for rows.Next() {
		rows.Scan(&idFile)

		filename := "files/" + idFile

		fileErr := os.Remove(filename)
		if fileErr != nil {
			fmt.Println("Otra cosa que falla")
		}
	}

	// BORRADO DE LAS VERSIONES DEL FICHERO
	stmtOut, err = db.Prepare(`
		DELETE FROM versions WHERE file_id = ?`)
	if err != nil {
		log.Panicln("Error de sintaxis al eliminar las versiones de un fichero de la BD:")
		log.Panic(err.Error())
	}
	_, queryError = stmtOut.Exec(originalFileID)
	if queryError != nil {
		log.Panicln("Error al eliminar las versiones de un fichero de la BD:")
		log.Panic(queryError.Error())
	}

	// BORRADO DEL FICHERO
	stmtOut, err = db.Prepare(`
		DELETE FROM files
		WHERE path IN (
			SELECT f2.path
			FROM (SELECT * FROM files) as f2
			WHERE f2.id = ?
		)
	`)
	if err != nil {
		log.Panicln("Error de sintaxis al eliminar un fichero de la BD:")
		log.Panic(err.Error())
	}

	_, queryError = stmtOut.Exec(originalFileID)
	if queryError != nil {
		log.Panicln("Error al eliminar un fichero de la BD:")
		log.Panic(queryError.Error())
	}

	stmtOut.Close()

	w.Write([]byte("Fichero eliminado correctamente"))
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
		log.Panicln("Error al instanciar el cifrador AES:")
		log.Panic(err)
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
		log.Panicln("Error al hacer hash + salt de la contraseña:")
		log.Panic(err)
	}

	return hashedPassword
}

func sendMail(email string, subject string, message string) bool {

	log.Println("Intentando abrir conexión con el servidor de correo...")

	// Set up authentication information.
	conn, err := net.Dial("tcp", "smtp.gmail.com:465")
	if err != nil {
		log.Println("Error al conectar con el servidor de correo:")
		log.Print(err)

		return false
	}
	auth := smtp.PlainAuth(
		"",
		"hypercloud17@gmail.com",
		"hypercloud17",
		"smtp.gmail.com",
	)

	// TLS
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "smtp.gmail.com",
	}

	conn = tls.Client(conn, tlsconfig)
	client, err := smtp.NewClient(conn, "smtp.gmail.com")

	log.Println("Conexión con el servidor de correo satisfactoria")

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	client.StartTLS(tlsconfig)

	client.Auth(auth)
	client.Mail("hypercloud17@gmail.com")
	client.Rcpt(email)
	w, err := client.Data()
	bodyMail := bytes.NewBufferString(message)
	_, err = bodyMail.WriteTo(w)
	err = w.Close()
	client.Quit()

	log.Println("Intentando enviar correo...")
	if err != nil {
		log.Fatalln("Error al enviar el correo")
		log.Fatal(err)

		return false
	}

	log.Println("Correo enviado correctamente")

	return true

}

func generateCode(email string) int {

	code := utils.Random(100000, 99999999)

	stmtIns, err := db.Prepare("UPDATE users SET loginCod = ?, timeValid = ? WHERE email = ?")
	if err != nil {
		log.Panicln("Error de sintaxis al registrar código de verificación de un usuario:")
		log.Fatal(err.Error())
	}
	defer stmtIns.Close()

	_, queryError := stmtIns.Exec(code, time.Now().Add(time.Hour).Unix(), email)
	if queryError != nil {
		log.Panicln("Error al registrar el código de verificación de un usuario:")
		log.Panic(queryError.Error())
	}

	return code
}

func checkAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")

		tokens := strings.Split(header, " ")

		if tokens[0] == "Bearer" {

			token, _ := jwt.Parse(tokens[1], func(token *jwt.Token) (interface{}, error) {
				return []byte(os.Getenv("APP_KEY")), nil
			})

			if token.Valid && checkIfUserExists(token.Claims.(jwt.MapClaims)["user"].(string)) {
				h.ServeHTTP(w, r)

			} else {
				w.Write([]byte("Token no valido"))
				log.Printf("Token del usuario '%s' NO válido\n", token.Claims.(jwt.MapClaims)["user"])
			}

		} else {
			log.Println("La autenticación no es mediante JWT")
		}
	})
}

// Funcion que se ejecuta antes que main
func init() {
	// Carga las variables de entorno
	gotenv.Load()
}

func main() {

	f, err := os.OpenFile("logs/server.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)

	connectToDatabase()
	defer db.Close()
	//getUsers()

	r := mux.NewRouter()
	r.HandleFunc("/users", getUsers)
	r.HandleFunc("/register", registerUser)
	r.HandleFunc("/login", loginUser)
	r.HandleFunc("/verify", verifyCode)

	subrouter := r.PathPrefix("/private").Subrouter()
	subrouter.Use(checkAuth)
	subrouter.HandleFunc("/upload", upload)
	subrouter.HandleFunc("/files", getFiles)
	subrouter.HandleFunc("/versions", getVersions)
	subrouter.HandleFunc("/download", downloadFile)
	subrouter.HandleFunc("/delete", deleteFile)

	//http.Handle("/", r)
	log.Println("Servidor HTTP a la escucha en el puerto 8443")
	http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", r)

}
