package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"bytes"
	"Hypercloud-Sync/utils"
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

var conn *tls.Conn



// Pregunta al usuario los datos de registro y
// devuelve un 'registerRequest' con ellos
func register() {
	var email, password, name string

	fmt.Print("Name: ")
	fmt.Scanf("%s\n", &name)
	fmt.Print("Email: ")
	fmt.Scanf("%s\n", &email)
	fmt.Print("Password: ")
	fmt.Scanf("%s\n", &password)

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
	fmt.Print("Password: ")
	fmt.Scanf("%s\n", &password)

	userData := loginRequest{
		Email:    email,
		Password: utils.Hash(password),
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


func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}


	//log.Println("client: connected to: ", conn.RemoteAddr())

	//state := conn.ConnectionState()
	/*for _, v := range state.PeerCertificates {
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println(v.Subject)
	}*/
	//log.Println("client: handshake: ", state.HandshakeComplete)
	//log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

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
