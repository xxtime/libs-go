package main

import (
	"fmt"
	"github.com/zlabwork/go-zlibs"
)

func main() {

	sampleAES()
}

func sampleAES() {
	key := []byte("ceb50761f4c378e1bc2f8a7585fb572d")
	text := []byte("this is test data")

	aes := zlibs.NewAesLib()

	// encrypt
	ciphertext, err := aes.Encrypt(key, text, zlibs.CBCCipher)
	if err != nil {
		fmt.Println(err)
	}

	// decrypt
	plaintext, err := aes.Decrypt(key, ciphertext, zlibs.CBCCipher)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(plaintext))
}
