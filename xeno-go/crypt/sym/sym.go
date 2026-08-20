package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func RandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}

	return bytes, nil

}

func EncryptAES256CBC(plaintext string, key []byte) string {
	bKey := key
	bIV, _ := RandomBytes(aes.BlockSize)

	blockSize := aes.BlockSize

	bPlaintext := PKCS5Padding([]byte(plaintext), blockSize, len(plaintext))
	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(bPlaintext)+aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], bPlaintext)

	copy(ciphertext, bIV)

	return hex.EncodeToString(ciphertext)
}

func DecryptAES256CBC(ciphertext string, key []byte) (string, error) {

	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes for AES-256")
	}

	cipherData, err := hex.DecodeString(ciphertext)
	if err != nil {

		return "", err
	}

	if len(cipherData) < aes.BlockSize {
		fmt.Printf("cipherText too short\r\n")
		return "", fmt.Errorf("cipherText too short")
	}

	iv := cipherData[:aes.BlockSize]
	cipherText := cipherData[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {

		return "", err
	}

	if len(cipherText)%aes.BlockSize != 0 {

		return "", fmt.Errorf("cipherText is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plainText := make([]byte, len(cipherText)*2)
	mode.CryptBlocks(plainText, cipherText)

	return string(plainText), nil
}

func EncryptAESGCM(key []byte, file_byte []byte) ([]byte, error) {

	var ret_byte []byte = make([]byte, 0)

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

	nonceSize := gcm.NonceSize()
	if len(file_byte) < nonceSize {
		return ret_byte, fmt.Errorf("failed to encrypt with symmetric key: %s", err.Error())
	}
	ciphertext := gcm.Seal(nil, nonce, file_byte, nil)

	ret_byte = append(ret_byte, nonce...)

	ret_byte = append(ret_byte, ciphertext...)

	return ret_byte, nil

}

func DecryptAESGCM(key []byte, file_byte []byte) ([]byte, error) {

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

	plainfile, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ret_byte, fmt.Errorf("failed to decrypt with symmetric key: %s", err.Error())
	}

	ret_byte = plainfile

	return ret_byte, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
