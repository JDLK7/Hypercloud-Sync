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
	"github.com/fatih/color"
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

var baseURL string
var userHash []byte;
var userJwtToken string;

func clearScreen() {
	print("\033[H\033[2J")
}

// Pregunta al usuario los datos de registro y
// devuelve un 'registerRequest' con ellos
func register() {
	var email, password, name string

	clearScreen()
	fmt.Print("Name: ")
	fmt.Scanf("%s\n", &name)
	fmt.Print("Email: ")
	fmt.Scanf("%s\n", &email)
	
	fmt.Print("Password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	password = string(bytePassword)
	fmt.Println()

	userData := registerRequest{
		Name:     name,
		Email:    email,
		Password: utils.Hash(password),
	}

	request, _ := json.Marshal(userData)


	res, err := http.Post(fmt.Sprintf("%s/register", baseURL), "application/json", bytes.NewBuffer(request))
	if err != nil {
		clearScreen()
		color.Red("\nError al realizar el registro\n")
		color.Red("Compruebe su conexión y vuelva a intentarlo\n\n")
		
		return
	}

	body := res.Body

	p := make([]byte, 30)
	n, err := body.Read(p)

	clearScreen()
	color.Blue("Respuesta del servidor: %s\n\n", string(p[:n]))
	menuScreen()
}

func login() {
	var email, password string

	clearScreen()
	fmt.Print("Email: ")
	fmt.Scanf("%s\n", &email)
	
	fmt.Print("Password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	password = string(bytePassword)
	fmt.Println()

	hashedPass := utils.Hash(password)
	userData := loginRequest{
		Email:    email,
		Password: hashedPass,
	}

	request, _ := json.Marshal(userData)

	res, err := http.Post(fmt.Sprintf("%s/login", baseURL), "application/json", bytes.NewBuffer(request))
	if err != nil {
		clearScreen()
		color.Red("\nError al realizar el login\n")
		color.Red("Compruebe su conexión y vuelva a intentarlo\n\n")

		return
	}
	body := res.Body

	p := make([]byte, 255)
	n, err := body.Read(p)

	clearScreen()

	if res.StatusCode == 401 {
		color.Red("Respuesta del servidor: %s\n\n", string(p[:n]))
	} else {
		color.Green("Respuesta del servidor: %s\n\n", string(p[:n]))
		requestAccessCode(email, hashedPass)
	}
}

func clearSession() {
	os.Remove("token")
	os.Remove("hash")
}

func requestAccessCode(email string, hashedPass string){
	var codigo string
	fmt.Print("Codigo: H-")
	fmt.Scanf("%s\n", &codigo)

	verifyData := verifyRequest{
		Email: email,
		Code: codigo,
	}

	request, _ := json.Marshal(verifyData)
	res, _ := http.Post(fmt.Sprintf("%s/verify", baseURL), "application/json", bytes.NewBuffer(request))

	fmt.Println("Comprobando credenciales...")

	body := res.Body
	p := make([]byte, 255)
	n, _ := body.Read(p)

	var verifyDataResponse map[string]interface{}

	json.Unmarshal(p[:n], &verifyDataResponse)

	// Meter condicion de status code para comprobar si el login es incorrecto
	fmt.Println(verifyDataResponse["message"])

	if verifyDataResponse["ok"].(bool) {
		userHash, _ = base64.StdEncoding.DecodeString(hashedPass)

		userJwtToken = verifyDataResponse["jwt"].(string)
		file, err := os.Create("./token")
		file2, err2 := os.Create("./hash")
		if err != nil || err2 != nil {
			color.Red("No se han podido crear los archivos necesarios para guardar la sesión")
			panic(err)
		}

		n , err := io.Copy(file, bytes.NewBuffer([]byte(verifyDataResponse["jwt"].(string))))
		n2 , err2 := io.Copy(file2, bytes.NewBuffer([]byte(userHash)))
		if err != nil || err2 != nil{
			color.Red("No se han podido guardar los datos de la sesión")
			panic(err)
			panic(n)
			panic(n2)
		}
		
		clearScreen()
		color.Green(verifyDataResponse["message"].(string) + "\n\n")

		privateMenuScreen()
	} else {
		clearScreen()
		color.Red(verifyDataResponse["message"].(string) + "\n\n")
	}
}

func download(isVersion bool) {

	var files []types.File

	if isVersion {
		files = listFileVersions()
	} else {
		files = listFiles()
	}

	if files == nil {
		return
	}

	var id = -1

	if isVersion {
		fmt.Print("Selecciona una versión: ")
	} else {
		fmt.Print("Selecciona un fichero: ")
	}

	fmt.Scanf("%d", &id)

	if id < 0 || id >= len(files) {
		clearScreen()
		color.Set(color.FgRed)
		defer color.Unset()

		if isVersion {
			fmt.Println("\nLa versión seleccionada no existe\n")
		} else {
			fmt.Println("\nEl fichero seleccionado no existe\n")
		}
	} else {

		var file = files[id]

		var fileRequest = types.FileDownloadRequest{
			Id: file.Id,
		}

		request, _ := json.Marshal(fileRequest)

		req, err := http.NewRequest("POST", fmt.Sprintf("%s/private/download", baseURL), bytes.NewBuffer(request))
		if err != nil {
			panic(err)
		}

		req.Header.Set("Authorization", "Bearer " + userJwtToken)

		res, err := (&http.Client{}).Do(req)
		if err != nil {
			clearScreen()
			color.Red("\nError al realizar la descarga del fichero\n")
			color.Red("Compruebe su conexión y vuelva a intentarlo\n\n")
	
			return
		}
		defer res.Body.Close()

		size, _ := strconv.ParseInt(res.Header.Get("X-Size"), 10, 64)
		p := make([]byte, size)
		n, _ := res.Body.Read(p)

		saveFile(p[:n], res.Header.Get("X-Filename"))
	}
}

func saveFile(fileEncryptBytes []byte, fileNameIn string) {

	clearScreen()

	filename, err := dialog.File().Save()
	if err != nil {
		color.Yellow("\nSe ha cancelado la descarga del fichero\n\n")
	} else {
		fileDecrypt, _ := utils.Decrypt(string(fileEncryptBytes), []byte(userHash[len(userHash)/2:]))
		ioutil.WriteFile(filename, []byte(fileDecrypt), 0777)
	}
}

func listFiles() []types.File {

	clearScreen()

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/private/files", baseURL), bytes.NewBuffer([]byte("")))

	req.Header.Set("Authorization", "Bearer " + userJwtToken)

	res, err := (&http.Client{}).Do(req)
	if err != nil {
		clearScreen()
		color.Red("\nError al listar los ficheros\n")
		color.Red("Compruebe su conexión y vuelva a intentarlo\n\n")

		return nil
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
		color.Set(color.FgGreen)
		defer color.Unset()

		for index, file := range files {
			fmt.Printf("%d. %s\n", index, string(file.Name))
		}

		fmt.Println()
	}

	return files

}

func listFileVersions() []types.File {

	var files = listFiles()

	var id = -1

	fmt.Print("Selecciona un fichero: ")
	fmt.Scanf("%d", &id)

	var file types.File
	
	if id < 0 || id >= len(files) {
		clearScreen()
		color.Red("\nEl fichero seleccionado no existe\n\n")

		return nil
	}

	clearScreen()
	
	file = files[id]

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/private/versions?file=%s", baseURL, file.Id), bytes.NewBuffer([]byte("")))
	req.Header.Set("Authorization", "Bearer " + userJwtToken)
	
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		clearScreen()
		color.Red("\nError al listar las versiones del fichero\n")
		color.Red("Compruebe su conexión y vuelva a intentarlo\n\n")

		return nil
	}

	defer res.Body.Close()

	size, _ := strconv.ParseInt(res.Header.Get("X-ResponseSize"), 10, 64)

	p := make([]byte, size)
	n, _ := res.Body.Read(p)

	var filesResponse types.FilesResponse

	json.Unmarshal(p[:n], &filesResponse)
	var versions = make([]types.File, 0)
	
	if filesResponse.Ok {
		versions = filesResponse.Files

		fmt.Println("\nListado de versiones: \n")
		color.Set(color.FgGreen)
		defer color.Unset()

		for index, version := range versions {
			fmt.Printf("%d. %s - %s\n", index, string(version.Name), string(version.Date))
		}

		fmt.Println()
	}

	return versions
}

func privateMenu() string {

	color.Cyan("\nMenú principal\n\n")

	var opt string
	fmt.Println("1. Subir fichero")
	fmt.Println("2. Listar ficheros")
	fmt.Println("3. Listar versiones de un fichero")
	fmt.Println("4. Descargar fichero")
	fmt.Println("5. Descargar versión de un fichero")
	fmt.Println("----------------------------------")
	fmt.Println("s. Cerrar sesión")
	fmt.Println("q. Salir\n")
	fmt.Print("Opción: ")
	fmt.Scanf("%s\n", &opt)

	return opt
}

func uploadFile() {

	chiperFile, filename := selectFile()

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/private/upload", baseURL), bytes.NewBuffer(chiperFile))

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
		clearSession()
		menuScreen()
	}

}

func selectFile() ([]byte, string){

	filename, err := dialog.File().Title("Select file").Load()
	clearScreen()

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
	fmt.Println("q. Salir")
	fmt.Print("Opción: ")
	fmt.Scanf("%s\n", &opt)

	return opt
}

// Funcion que se ejecuta antes que main
func init() {
	// Carga las variables de entorno
	gotenv.Load()

	baseURL = fmt.Sprintf("https://%s:%s", os.Getenv("SERVER_HOST"), os.Getenv("SERVER_PORT"))
}

func readPasswords() {

	file, err := os.Open("./token")
	if err != nil {
		return
	}

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

func menuScreen() {
	var opt = "0"
	for opt != "q" && opt != "Q" {
		opt = menu()
		switch opt {
			case "1":
				register()
				break
			case "2":
				login()
				break
			default: clearScreen()
		}
	}
}

func privateMenuScreen() {
	var opt = "0"
	for opt != "q" && opt != "Q" && opt != "s" && opt != "S" {
		opt = privateMenu()
		switch opt {
			case "1": uploadFile()
				break
			case "2": listFiles()
				break
			case "3": listFileVersions()
				break
			case "4": download(/*isVersion*/ false) 
				break
			case "5": download(/*isVersion*/ true)
				break
			case "s":
				clearSession() 
				clearScreen()
				break
			default: clearScreen()
		}
	}
}

func main() {

	clearScreen()
	color.Cyan("Bienvenid@ a HyperCloud-Sync®\n\n")

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")

	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	readPasswords();

	if userJwtToken != "" {
		privateMenuScreen()
	} else {
		menuScreen()
	}
}
