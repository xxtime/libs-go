package libsgo

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func NewRsaLib() *RsaLib {
	return &RsaLib{
		padding: OPENSSL_PKCS1_PADDING,
	}
}

type RsaLib struct {
	priKey  *rsa.PrivateKey
	pubKey  *rsa.PublicKey
	padding int
}

func (lib *RsaLib) GeneratePrivateKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (lib *RsaLib) SetPadding(padding int) {
	lib.padding = padding
}

func (lib *RsaLib) GetPrivateKey() *rsa.PrivateKey {
	return lib.priKey
}

func (lib *RsaLib) SetPrivateKey(privateKey []byte) error {
	block, _ := pem.Decode(privateKey)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return errors.New("failed to decode PEM block containing private key")
	}

	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	lib.priKey = priKey
	return nil
}

func (lib *RsaLib) GetPublicKey() *rsa.PublicKey {
	return lib.pubKey
}

func (lib *RsaLib) SetPublicKey(publicKey []byte) error {
	block, _ := pem.Decode(publicKey)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("failed to decode PEM block containing public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	lib.pubKey = pubInterface.(*rsa.PublicKey)
	return nil
}

func (lib *RsaLib) Encrypt(plaintext []byte) ([]byte, error) {
	if lib.pubKey == nil {
		return nil, errors.New("no public key")
	}
	switch lib.padding {
	case OPENSSL_PKCS1_PADDING:
		return rsa.EncryptPKCS1v15(rand.Reader, lib.pubKey, plaintext)
	default:
		return rsa.EncryptOAEP(sha1.New(), rand.Reader, lib.pubKey, plaintext, nil)
	}
}

func (lib *RsaLib) Decrypt(ciphertext []byte) ([]byte, error) {
	if lib.priKey == nil {
		return nil, errors.New("no private key")
	}
	switch lib.padding {
	case OPENSSL_PKCS1_PADDING:
		return rsa.DecryptPKCS1v15(rand.Reader, lib.priKey, ciphertext)
	default:
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, lib.priKey, ciphertext, nil)
	}
}

func (lib *RsaLib) SignWithSha1(data []byte) ([]byte, error) {
	h := sha1.New()
	h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, lib.priKey, crypto.SHA1, h.Sum(nil))
}

func (lib *RsaLib) SignWithSha256(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, lib.priKey, crypto.SHA256, h.Sum(nil))
}

func (lib *RsaLib) SignVerifySha1(data []byte, sign []byte) bool {
	h := sha1.New()
	h.Write(data)
	if err := rsa.VerifyPKCS1v15(lib.pubKey, crypto.SHA1, h.Sum(nil), sign); err != nil {
		return false
	}
	return true
}

func (lib *RsaLib) SignVerifySha256(data []byte, sign []byte) bool {
	h := sha256.New()
	h.Write(data)
	if err := rsa.VerifyPKCS1v15(lib.pubKey, crypto.SHA256, h.Sum(nil), sign); err != nil {
		return false
	}
	return true
}
