package libsgo

import (
	"errors"
	"encoding/pem"
	"crypto"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/sha1"
	"crypto/sha256"
)

func NewRsaLib() *rsaLib {
	return &rsaLib{
		padding: OPENSSL_PKCS1_PADDING,
	}
}

type rsaLib struct {
	priKey  *rsa.PrivateKey
	pubKey  *rsa.PublicKey
	padding int
}

func (r *rsaLib) GeneratePrivateKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (r *rsaLib) SetPadding(padding int) {
	r.padding = padding
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
	switch r.padding {
	case OPENSSL_PKCS1_PADDING:
		return rsa.EncryptPKCS1v15(rand.Reader, r.pubKey, plaintext)
	default:
		return rsa.EncryptOAEP(sha1.New(), rand.Reader, r.pubKey, plaintext, nil)
	}
}

func (r *rsaLib) Decrypt(ciphertext []byte) ([]byte, error) {
	if r.priKey == nil {
		return nil, errors.New("no private key")
	}
	switch r.padding {
	case OPENSSL_PKCS1_PADDING:
		return rsa.DecryptPKCS1v15(rand.Reader, r.priKey, ciphertext)
	default:
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, r.priKey, ciphertext, nil)
	}
}

func (r *rsaLib) SignWithSha1(data []byte) ([]byte, error) {
	h := sha1.New()
	h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, r.priKey, crypto.SHA1, h.Sum(nil))
}

func (r *rsaLib) SignWithSha256(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, r.priKey, crypto.SHA256, h.Sum(nil))
}

func (r *rsaLib) SignVerifySha1(data []byte, sign []byte) bool {
	h := sha1.New()
	h.Write(data)
	if err := rsa.VerifyPKCS1v15(r.pubKey, crypto.SHA1, h.Sum(nil), sign); err != nil {
		return false
	}
	return true
}

func (r *rsaLib) SignVerifySha256(data []byte, sign []byte) bool {
	h := sha256.New()
	h.Write(data)
	if err := rsa.VerifyPKCS1v15(r.pubKey, crypto.SHA256, h.Sum(nil), sign); err != nil {
		return false
	}
	return true
}
