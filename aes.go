package zlibs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

type Cipher int

const (
	CBCCipher Cipher = iota
	CFBCipher
)

/**
 * @docs https://golang.org/src/crypto/cipher/example_test.go
 * @docs https://blog.csdn.net/whatday/article/details/98292648
 * @docs https://segmentfault.com/a/1190000021267253
 * @docs http://www.361way.com/golang-rsa-aes/5828.html
 */

func NewAesLib() *AesLib {
	return &AesLib{}
}

type AesLib struct {
}

func (lib *AesLib) Encrypt(key []byte, plaintext []byte, cipher Cipher) ([]byte, error) {
	if cipher == CBCCipher {
		return lib.cbcEncrypt(key, plaintext)
	}
	if cipher == CFBCipher {
		return lib.cfbEncrypt(key, plaintext)
	}
	return nil, fmt.Errorf("error cipher")
}

func (lib *AesLib) Decrypt(key []byte, ciphertext []byte, cipher Cipher) ([]byte, error) {
	if cipher == CBCCipher {
		return lib.cbcDecrypt(key, ciphertext)
	}
	if cipher == CFBCipher {
		return lib.cfbDecrypt(key, ciphertext)
	}
	return nil, fmt.Errorf("error cipher")
}

func (lib *AesLib) cfbEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func (lib *AesLib) cfbDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func (lib *AesLib) cbcEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = pkcs7Padding(plaintext, aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func (lib *AesLib) cbcDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext) // CryptBlocks can work in-place if the two arguments are the same.

	return pkcs7UnPadding(ciphertext, aes.BlockSize)
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func pkcs7UnPadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > blockSize {
		return nil, errors.New("aes error padding")
	}
	return data[:(length - unpadding)], nil
}
