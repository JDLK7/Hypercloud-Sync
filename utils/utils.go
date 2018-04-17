package utils

import (
	"crypto/sha512"
	"encoding/base64"
	"time"
	mRand "math/rand"
	cRand "crypto/rand"
	"crypto/aes"
	"io"
	"crypto/cipher"
	"io/ioutil"
)

// Devuelve el hash de la contraseña en base64.
func Hash(password string) string {
	hasher := sha512.New()
	hasher.Write([]byte(password))

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

func Random(min, max int) int {
	mRand.Seed(time.Now().Unix())
	return mRand.Intn(max - min) + min
}

func CheckTime(start, end time.Time) bool {

	return start.Before(end)
}


// Devuelve la clave cifrada con la "pimienta" en base64.
func Encrypt(text []byte, key []byte) []byte {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(cRand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], text)


	return ciphertext
	// create a new file for saving the encrypted data.
	/*f, err := os.Create("a_aes.pdf")
	if err != nil {
		panic(err.Error())
	}
	_, err = io.Copy(f, bytes.NewReader(ciphertext))
	if err != nil {
		panic(err.Error())
	}*/

	// done
}

// Devuelve la clave descifrada como []byte
func Decrypt(ciphertext []byte, key []byte, name string) {

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Before even testing the decryption,
	// if the text is too small, then it is incorrect
	if len(ciphertext) < aes.BlockSize {
		panic("Text is too short")
	}

	// Get the 16 byte IV
	iv := ciphertext[:aes.BlockSize]

	// Remove the IV from the ciphertext
	ciphertext = ciphertext[aes.BlockSize:]

	// Return a decrypted stream
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt bytes from ciphertext
	stream.XORKeyStream(ciphertext, ciphertext)

	ioutil.WriteFile(name, ciphertext, 0777)
}