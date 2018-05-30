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
	"github.com/subosito/gotenv"
	"io/ioutil"
	"io"
	"Hypercloud-Sync/types"
	"golang.org/x/crypto/ssh/terminal"
	"syscall"
	"encoding/base64"
	"strconv"
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

var userHash []byte;
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
		userHash, _ = base64.StdEncoding.DecodeString(hashedPass)

		userJwtToken = verifyDataResponse["jwt"].(string)
		file, err := os.Create("./token")
		file2, err2 := os.Create("./hash")
		if err != nil && err2 != nil {
			panic(err)
		}
		n , err := io.Copy(file, bytes.NewBuffer([]byte(verifyDataResponse["jwt"].(string))))
		n2 , err2 := io.Copy(file2, bytes.NewBuffer([]byte(userHash)))
		if err != nil && err2 != nil{
			panic(err)
			panic(n)
			panic(n2)
		}
		
		var opt = "0"
		for opt != "3" {
			opt = privateMenu()
			switch opt {
			case "1": uploadFile()
				break
			case "2": listFiles()
				break
			case "3": download()

			}
		}




	}
}

func download()  {

	var files = listFiles()

	var id = -1
	fmt.Print("Selecciona un fichero: ")
	fmt.Scanf("%d", &id)
	if id < 0 || id > len(files) {
		fmt.Println("El fichero seleccionado no existe")
	} else {

		var file = files[id]

		var fileRequest = types.FileDownloadRequest{
			Id: file.Id,
		}

		request, _ := json.Marshal(fileRequest)

		req, err := http.NewRequest("POST", "https://127.0.0.1:8443/private/download", bytes.NewBuffer(request))

		if err != nil {
			panic(err)
		}

		req.Header.Set("Authorization", "Bearer " + userJwtToken)

		res, err := (&http.Client{}).Do(req)

		if err != nil {
			panic(err)
		}
		defer res.Body.Close()

		size, _ := strconv.ParseInt(res.Header.Get("X-Size"), 10, 64)
		fmt.Println(size)
		p := make([]byte, size)
		n, _ := res.Body.Read(p)

		saveFile(p[:n], res.Header.Get("X-Filename"))
	}


}

func saveFile(fileEncryptBytes []byte, fileNameIn string)  {

	filename, err := dialog.File().Save()


	if err != nil {
		panic(err)
	}

	fmt.Println(len(fileEncryptBytes))
	fileDecrypt, err := utils.Decrypt(string(fileEncryptBytes), []byte(userHash[len(userHash)/2:]))

	ioutil.WriteFile(filename, []byte(fileDecrypt), 0777)

}

func listFiles() []types.File{

	req, err := http.NewRequest("GET", "https://127.0.0.1:8443/private/files", bytes.NewBuffer([]byte("")))

	req.Header.Set("Authorization", "Bearer " + userJwtToken)

	res, err := (&http.Client{}).Do(req)

	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	p := make([]byte, 255)
	n, _ := res.Body.Read(p)

	var filesResponse types.FilesResponse

	json.Unmarshal(p[:n], &filesResponse)
	var files = make([]types.File, 0)
	if filesResponse.Ok {
		files = filesResponse.Files
		fmt.Println("\nListado de ficheros: \n")
		for index, file := range files {

			fmt.Printf("%d. %s\n", index, string(file.Name))
		}

		fmt.Println()
	}

	return files

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

	if string(message) == "Token no valido" {
		fmt.Println("Sesión caducada")
		login()
	}

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

	key := []byte(userHash[len(userHash)/2:])

	cipheredText, err := utils.Encrypt(data, key)

	return []byte(cipheredText), filename

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

func readPasswords() {

	file, err := os.Open("./token")
	file2, err := os.Open("./hash")

	fi, err := file.Stat()
	data := make([]byte, fi.Size())
	data2 := make([]byte, fi.Size())
	count, err := file.Read(data)
	count2, err2 := file2.Read(data2)

	if err != nil {
		userJwtToken = ""
	} else {
		userJwtToken = string(data[:count])
	}

	if err2 != nil {
		userHash = make([]byte, 256)
	} else {
		userHash = data[:count2]
	}

}

func main() {

	readPasswords();

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")

	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}


	if userJwtToken != "" {
		var opt = "0"
		for opt != "3" {
			opt = privateMenu()
			switch opt {
			case "1": uploadFile()
				break
			case "2": listFiles()
				break
			case "3": download()

			}
		}
	} else {
		var opt= "0"
		for opt != "3" {
			opt = menu()
			switch opt {
			case "1":
				register()
				break
			case "2":
				login()
			}
		}
	}
}
