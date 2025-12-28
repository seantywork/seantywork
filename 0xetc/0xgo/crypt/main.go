package main

import (
	"log"

	pkgsym "github.com/seantywork/linuxyz/go/crypt/sym"
)

func main() {

	/*
		key := "12345678123456781234567812345678"

		ciphertext := "7c1c5afe5fc1d2cda983019029a65490c3f2fc7fb752fff310406549ea52350edbe40cb8448b9a9a15e0bb02ed0a97244387c396125a6636ed3e9ee74517ab29"

		dap, err := pkgsym.DecryptAES256CBC(ciphertext, []byte(key))

		if err != nil {

			log.Fatalf("err: %v\n", err)
		} else {
			log.Printf("success: %v\n", dap)
		}
	*/

	key := []byte("12345678123456781234567812345678")

	data := "Scroll through the sentence list to see the sentence that best meets the context you’re looking for."

	cipher := pkgsym.EncryptAES256CBC(data, key)

	decipher, err := pkgsym.DecryptAES256CBC(cipher, key)

	if err != nil {

		log.Fatalf("error: %v\n", err)
	} else {

		log.Printf("success: %s\n", decipher)
	}

	cipherb, err := pkgsym.EncryptAESGCM(key, []byte(data))

	if err != nil {
		log.Fatalf("error: %v\n", err)
	}

	decipherb, err := pkgsym.DecryptAESGCM(key, cipherb)
	if err != nil {

		log.Fatalf("error: %v\n", err)
	} else {

		log.Printf("success: %s\n", string(decipherb))
	}
}
