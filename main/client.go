package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"bytes"
	"Hypercloud-Sync/utils"
	//"github.com/skratchdot/open-golang/open"
	//"github.com/sqweek/dialog"
	"github.com/sqweek/dialog"
	"os"
	"encoding/base64"
	"github.com/subosito/gotenv"
	"io/ioutil"
	"io"
	"Hypercloud-Sync/types"
	"golang.org/x/crypto/ssh/terminal"
	"syscall"
)

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type verifyRequest struct {
	Email    string `json:"email"`
	Code string `json:"code"`
}

var conn *tls.Conn

var userToken string;
var userJwtToken string;

// Pregunta al usuario los datos de registro y
// devuelve un 'registerRequest' con ellos
func register() {
	var email, password, name string

	fmt.Print("Name: ")
	fmt.Scanf("%s\n", &name)
	fmt.Print("Email: ")
	fmt.Scanf("%s\n", &email)
	
	fmt.Print("Password:\n")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
    password = string(bytePassword)

	userData := registerRequest{
		Name:     name,
		Email:    email,
		Password: utils.Hash(password),
	}

	request, _ := json.Marshal(userData)


	res, err := http.Post("https://127.0.0.1:8443/register", "application/json", bytes.NewBuffer(request))

	if err != nil {
		log.Fatalf("client: write: %s", err)
	}
	body := res.Body

	p := make([]byte, 30)
	n, err := body.Read(p)
	fmt.Println(string(p[:n]))
}

func login() {
	var email, password string

	fmt.Print("Email: ")
	fmt.Scanf("%s\n", &email)
	fmt.Print("Password:\n")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
    password = string(bytePassword)

	hashedPass := utils.Hash(password)
	userData := loginRequest{
		Email:    email,
		Password: hashedPass,
	}

	request, _ := json.Marshal(userData)

	res, err := http.Post("https://127.0.0.1:8443/login", "application/json", bytes.NewBuffer(request))

	if err != nil {
		log.Fatalf("client: write: %s", err)
	}
	body := res.Body

	p := make([]byte, 255)
	n, err := body.Read(p)
	fmt.Println(string(p[:n]))

	requestAccessCode(email, hashedPass)

}

func requestAccessCode(email string, hashedPass string){
	var codigo string
	fmt.Print("Codigo: H-")
	fmt.Scanf("%s\n", &codigo)

	verifyData := verifyRequest{
		Email: email,
		Code: codigo,
	}
	fmt.Println("Intentando peticion")
	request, _ := json.Marshal(verifyData)
	res, _ := http.Post("https://127.0.0.1:8443/verify", "application/json", bytes.NewBuffer(request))
	fmt.Println("Peticion hecha")
	body := res.Body
	p := make([]byte, 255)
	n, _ := body.Read(p)

	var verifyDataResponse map[string]interface{}

	json.Unmarshal(p[:n], &verifyDataResponse)
	fmt.Println(verifyDataResponse["message"])

	if verifyDataResponse["ok"].(bool) {
		userToken = hashedPass
		userJwtToken = verifyDataResponse["jwt"].(string)
		file, err := os.Create("./token")
		if err != nil {
			panic(err)
		}
		n , err := io.Copy(file, bytes.NewBuffer([]byte(verifyDataResponse["jwt"].(string))))
		if err != nil {
			panic(err)
			panic(n)
		}
		
		var opt = "0"
		for opt != "3" {
			opt = privateMenu()
			switch opt {
			case "1": uploadFile()
				break
			case "2": listFiles()

			}


		}




	}
}

func listFiles() {

	req, err := http.NewRequest("GET", "https://127.0.0.1:8443/private/files", bytes.NewBuffer([]byte("")))

	req.Header.Set("Authorization", "Bearer " + userJwtToken)

	res, err := (&http.Client{}).Do(req)

	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	p := make([]byte, 255)
	n, _ := res.Body.Read(p)

	var verifyDataResponse types.FilesResponse

	json.Unmarshal(p[:n], &verifyDataResponse)

	if verifyDataResponse.Ok {
		var files = verifyDataResponse.Files
		fmt.Println("\nListado de ficheros: \n")
		for index, file := range files {

			fmt.Printf("%d. %s\n", index, string(file.Name))
		}

		fmt.Println()
	}

}

func privateMenu() string{

	var opt string
	fmt.Println("1. Subir fichero")
	fmt.Println("2. Listar ficheros")
	fmt.Println("3. Descargar fichero")
	fmt.Print("Opción: ")
	fmt.Scanf("%s\n", &opt)

	return opt
}

func uploadFile() {

	chiperFile, filename := selectFile()

	req, err := http.NewRequest("POST", "https://127.0.0.1:8443/private/upload", bytes.NewBuffer(chiperFile))

	req.Header.Set("Content-Type", "binary/octet-stream")
	req.Header.Set("Authorization", "Bearer " + userJwtToken)
	req.Header.Set("X-Filename", filename)

	res, err := (&http.Client{}).Do(req)

	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	message, _ := ioutil.ReadAll(res.Body)
	fmt.Printf(string(message))
}

func selectFile() ([]byte, string){

	fmt.Println("Abriendo dialogo")
	filename, err := dialog.File().Title("Select file").Load()
	fmt.Println("Dialogo abierto")


	if err != nil {
		log.Fatal(err)
	}

	file, err := os.Open(filename) // For read access.
	if err != nil {
		log.Fatal(err)
	}
	fi, err := file.Stat()
	data := make([]byte, fi.Size())
	count, err := file.Read(data)
	if err != nil {
		log.Fatal(count)
	}

	key, _ := base64.StdEncoding.DecodeString(os.Getenv("APP_KEY"))

	cipheredFile := utils.Encrypt(data, key)
	return cipheredFile, filename
	/*filenameEn, _ := dialog.File().Title("Export to XML").Load()
	fileEn, err := os.Open(filenameEn) // For read access.
	if err != nil {
		log.Fatal(err)
	}
	fiEn, err := fileEn.Stat()
	dataEn := make([]byte, fiEn.Size())
	countEn, err := fileEn.Read(dataEn)
	fmt.Println(dataEn)
	if err != nil {
		log.Fatal(countEn)
	}


	utils.Decrypt(dataEn, key)*/
	//fmt.Printf("read %d bytes: %q\n", count, data[:count])
	/*fileDecrypted := utils.Decrypt(string(fileEncrypted), key)

	ioutil.WriteFile("./prueba.pdf", fileDecrypted, 0777)
	ioutil.WriteFile("./pruebaDes.pdf", []byte(fileEncrypted), 0777)*/
}

func menu() string{
	var opt string
	fmt.Println("1. Registrarse")
	fmt.Println("2. Login")
	fmt.Println("3. Salir")
	fmt.Print("Opción: ")
	fmt.Scanf("%s\n", &opt)

	return opt
}

// Funcion que se ejecuta antes que main
func init() {
	// Carga las variables de entorno
	gotenv.Load()
}

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}


	var opt = "0"
	for opt != "3" {
		opt = menu()
		switch opt {
			case "1": register()
				break
			case "2": login()
		}
	}
}
