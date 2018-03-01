package main

import (
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
)

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// Devuelve el hash de la contraseña en base64.
func hash(password string) string {
	hasher := sha512.New()
	hasher.Write([]byte(password))

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

// Pregunta al usuario los datos de registro y
// devuelve un 'registerRequest' con ellos
func register() registerRequest {
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
		Password: hash(password),
	}

	return userData
}

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "127.0.0.1:8443", &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println(v.Subject)
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

	userData := register()

	request, _ := json.Marshal(userData)
	jsonRequest := string(request)

	n, err := io.WriteString(conn, jsonRequest)
	if err != nil {
		log.Fatalf("client: write: %s", err)
	}
	log.Printf("client: wrote %q (%d bytes)", jsonRequest, n)

	reply := make([]byte, 256)
	n, err = conn.Read(reply)
	log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)
	log.Print("client: exiting")
}
