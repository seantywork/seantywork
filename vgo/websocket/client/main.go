package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	"github.com/gorilla/websocket"
)

type CommJSON struct {
	Data string `json:"data"`
}

func run() error {

	certpool := x509.NewCertPool()

	file_ca, err := os.ReadFile("certs/ca.pem")

	if err != nil {

		return fmt.Errorf("failed to connect: read ca: %s", err.Error())
	}

	okay := certpool.AppendCertsFromPEM(file_ca)

	if !okay {

		return fmt.Errorf("failed to connect: add ca")
	}

	websocket.DefaultDialer.TLSClientConfig = &tls.Config{
		RootCAs: certpool,
	}

	c, _, err := websocket.DefaultDialer.Dial("wss://localhost:8888/hello", nil)

	if err != nil {

		return fmt.Errorf("failed to connect: dial: %s", err.Error())
	}

	req := CommJSON{
		Data: "hi",
	}

	resp := CommJSON{}

	err = c.WriteJSON(req)

	if err != nil {

		return fmt.Errorf("failed to write: %s", err.Error())

	}

	err = c.ReadJSON(&resp)

	if err != nil {

		return fmt.Errorf("failed to read: %s", err.Error())
	}

	log.Printf("server data: %s\n", resp.Data)

	return nil
}

func main() {

	if err := run(); err != nil {

		log.Fatal(err.Error())
	}

}
