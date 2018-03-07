package utils

import (
	"crypto/sha512"
	"encoding/base64"
	"time"
	"math/rand"
)

// Devuelve el hash de la contraseña en base64.
func Hash(password string) string {
	hasher := sha512.New()
	hasher.Write([]byte(password))

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

func Random(min, max int) int {
	rand.Seed(time.Now().Unix())
	return rand.Intn(max - min) + min
}