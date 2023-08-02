package x509components

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
)

// Fundamentals of Secure Communication: x509 certificate
// Fundamentals of Secure Communication: Asymmetric And Symmetric Cryptography
// related matters written in Go

func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {

	var pubkey *rsa.PublicKey

	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return privkey, pubkey, fmt.Errorf("failed to gen key pair: %s", err.Error())
	}

	pubkey = &privkey.PublicKey

	return privkey, pubkey, nil
}

func PrivateKeyToBytes(priv *rsa.PrivateKey) ([]byte, error) {
	var ret_byte []byte
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	if privBytes == nil {
		return ret_byte, fmt.Errorf("failed to encode priv key to bytes: %s", "invalid")
	}

	return privBytes, nil
}

func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {

	var ret_byte []byte

	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return pubASN1, fmt.Errorf("failed to encode pub key to bytes: %s", err.Error())
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	if pubBytes == nil {
		return ret_byte, fmt.Errorf("failed to encode priv key to bytes: %s", "invalid")
	}

	return pubBytes, nil
}

func BytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {

	var privkey *rsa.PrivateKey

	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		fmt.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return privkey, fmt.Errorf("failed to decode bytes to priv key: %s", err.Error())
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return privkey, fmt.Errorf("failed to decode bytes to priv key: %s", err.Error())
	}
	return key, nil
}

func BytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {

	var pubkey *rsa.PublicKey

	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		fmt.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return pubkey, fmt.Errorf("failed to decode bytes to pub key: %s", err.Error())
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return pubkey, fmt.Errorf("failed to decode bytes to pub key: %s", err.Error())
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return pubkey, fmt.Errorf("failed to decode bytes to pub key: %s", err.Error())
	}
	return key, nil
}

func VerifyCertificate(pub_key_b []byte, cert_b []byte) error {

	block, _ := pem.Decode(cert_b)

	var cert *x509.Certificate

	cert, err := x509.ParseCertificate(block.Bytes)

	if err != nil {
		return fmt.Errorf("failed to verify cert: %s", err.Error())
	}

	hash_sha := sha256.New()

	hash_sha.Write(cert.RawTBSCertificate)

	hash_data := hash_sha.Sum(nil)

	pub_key, err := BytesToPublicKey(pub_key_b)

	if err != nil {
		return fmt.Errorf("failed to verify cert: %s", err.Error())
	}

	err = rsa.VerifyPKCS1v15(pub_key, crypto.SHA256, hash_data, cert.Signature)

	if err != nil {
		return fmt.Errorf("failed to generate challenge: %s", "invalid pub key")
	}

	return nil

}

func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return ciphertext, fmt.Errorf("failed to encrypt with public key: %s", err.Error())
	}
	return ciphertext, nil
}

func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return plaintext, fmt.Errorf("failed to decrypt with private key: %s", err.Error())
	}
	return plaintext, nil
}

func EncryptWithSymmetricKey(key []byte, file_byte []byte) ([]byte, error) {

	var ret_byte []byte

	c, err := aes.NewCipher(key)

	if err != nil {
		return ret_byte, fmt.Errorf("failed to encrypt with symmetric key: %s", err.Error())

	}

	gcm, err := cipher.NewGCM(c)

	if err != nil {
		return ret_byte, fmt.Errorf("failed to encrypt with symmetric key: %s", err.Error())

	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return ret_byte, fmt.Errorf("failed to encrypt with symmetric key: %s", err.Error())
	}

	enc_file := gcm.Seal(nonce, nonce, file_byte, nil)

	ret_byte = enc_file

	return ret_byte, nil

}

func DecryptWithSymmetricKey(key []byte, file_byte []byte) ([]byte, error) {

	var ret_byte []byte

	c, err := aes.NewCipher(key)
	if err != nil {
		return ret_byte, fmt.Errorf("failed to decrypt with symmetric key: %s", err.Error())
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return ret_byte, fmt.Errorf("failed to decrypt with symmetric key: %s", err.Error())
	}

	nonceSize := gcm.NonceSize()
	if len(file_byte) < nonceSize {
		return ret_byte, fmt.Errorf("failed to decrypt with symmetric key: %s", err.Error())
	}

	nonce, ciphertext := file_byte[:nonceSize], file_byte[nonceSize:]
	plain_file, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ret_byte, fmt.Errorf("failed to decrypt with symmetric key: %s", err.Error())
	}

	ret_byte = plain_file

	return ret_byte, nil
}
