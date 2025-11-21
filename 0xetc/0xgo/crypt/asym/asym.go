package pki

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	mathrand "math/rand"
	"time"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type CertSet struct {
	RootCertPEM   []byte
	RootKeyPEM    []byte
	RootPubPEM    []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	ClientPubPEM  []byte
	ServCertPEM   []byte
	ServKeyPEM    []byte
	ServPubPEM    []byte
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

func CertToBytes(crt *x509.Certificate) ([]byte, error) {

	cert_b := crt.Raw

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert_b,
	})

	if certBytes == nil {

		return nil, fmt.Errorf("failed to encode cert to bytes: %s", "invalid")
	}

	return certBytes, nil

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

func BytesToCert(cert []byte) (*x509.Certificate, error) {

	var ret_crt *x509.Certificate

	block, _ := pem.Decode(cert)

	ifc, err := x509.ParseCertificate(block.Bytes)

	if err != nil {

		return ret_crt, fmt.Errorf("failed to decode bytes to certificate: %s", err.Error())
	}

	ret_crt = ifc

	return ret_crt, nil
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

func GetRandIntInRange(min int, max int) int {

	mathrand.Seed(time.Now().UnixNano())

	return mathrand.Intn(max-min+1) + min
}

func GenKeyPair(keylen int) (*rsa.PrivateKey, *rsa.PublicKey) {

	bitSize := keylen

	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	pub := key.Public()

	return key, pub.(*rsa.PublicKey)
}

func CertTemplate(cn string, validYear int) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	if err != nil {

		return nil, fmt.Errorf("failed to gen cert tmpl: %s", err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: cn},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30 * 12 * time.Duration(validYear)),
		BasicConstraintsValid: true,
		DNSNames: []string{
			cn,
		},
	}
	return &tmpl, nil
}

func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)

	return
}

func NewCertsPipeline(server_name string, client_name string) *CertSet {
	// generate a new key-pair
	rootKey, rootPub := GenKeyPair(4096)

	rootCertTmpl, err := CertTemplate("ca", 10)
	if err != nil {
		log.Fatalf("creating cert template: %v", err)
	}

	// this cert will be the CA that we will use to sign the server cert
	rootCertTmpl.IsCA = true
	// describe what the certificate will be used for
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	log.Println("----------ca cert")

	rootCert, rootCertPEM, err := CreateCert(rootCertTmpl, rootCertTmpl, rootPub, rootKey)
	if err != nil {
		log.Fatalf("error creating cert: %v", err)
	}

	// provide the private key and the cert
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
	})

	rootPubPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rootPub),
	})

	/*******************************************************************
	Server Cert
	*******************************************************************/

	// create a key-pair for the server
	servKey, servPub := GenKeyPair(4096)

	log.Println("----------server cert")
	// create a template for the server
	servCertTmpl, err := CertTemplate(server_name, 1)
	if err != nil {
		log.Fatalf("creating cert template: %v", err)
	}
	servCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	servCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	// create a certificate which wraps the server's public key, sign it with the root private key
	_, servCertPEM, err := CreateCert(servCertTmpl, rootCert, servPub, rootKey)
	if err != nil {
		log.Fatalf("error creating cert: %v", err)
	}

	// provide the private key and the cert
	servKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(servKey),
	})

	servPubPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(servPub),
	})

	/*******************************************************************
	Client Cert
	*******************************************************************/

	// create a key-pair for the client
	clientKey, clientPub := GenKeyPair(4096)

	log.Println("----------client cert")

	// create a template for the client
	clientCertTmpl, err := CertTemplate(client_name, 1)
	if err != nil {
		log.Fatalf("creating cert template: %v", err)
	}
	clientCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	clientCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	// the root cert signs the cert by again providing its private key
	_, clientCertPEM, err := CreateCert(clientCertTmpl, rootCert, clientPub, rootKey)
	if err != nil {
		log.Fatalf("error creating cert: %v", err)
	}

	// encode and load the cert and private key for the client
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})

	clientPubPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(clientPub),
	})

	cs := CertSet{
		RootCertPEM:   rootCertPEM,
		RootKeyPEM:    rootKeyPEM,
		RootPubPEM:    rootPubPEM,
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
		ClientPubPEM:  clientPubPEM,
		ServCertPEM:   servCertPEM,
		ServKeyPEM:    servKeyPEM,
		ServPubPEM:    servPubPEM,
	}

	return &cs
}
