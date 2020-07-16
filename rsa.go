package libsgo

import (
	"encoding/pem"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
)

func NewRsaLib() *rsaLib {
	return &rsaLib{}
}

type rsaLib struct {
	priKey *rsa.PrivateKey
	pubKey *rsa.PublicKey
}

func (r *rsaLib) GeneratePrivateKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (r *rsaLib) GetPrivateKey() *rsa.PrivateKey {
	return r.priKey
}

func (r *rsaLib) SetPrivateKey(privateKey []byte) error {
	block, _ := pem.Decode(privateKey)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return errors.New("failed to decode PEM block containing private key")
	}

	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	r.priKey = priKey
	return nil
}

func (r *rsaLib) GetPublicKey() *rsa.PublicKey {
	return r.pubKey
}

func (r *rsaLib) SetPublicKey(publicKey []byte) error {
	block, _ := pem.Decode(publicKey)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("failed to decode PEM block containing public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	r.pubKey = pubInterface.(*rsa.PublicKey)
	return nil
}

func (r *rsaLib) Encrypt(plaintext []byte) ([]byte, error) {
	if r.pubKey == nil {
		return nil, errors.New("no public key")
	}
	return rsa.EncryptPKCS1v15(rand.Reader, r.pubKey, plaintext)
}

func (r *rsaLib) Decrypt(ciphertext []byte) ([]byte, error) {
	if r.priKey == nil {
		return nil, errors.New("no private key")
	}
	return rsa.DecryptPKCS1v15(rand.Reader, r.priKey, ciphertext)
}
