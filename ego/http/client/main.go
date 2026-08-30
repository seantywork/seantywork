package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

type CommJSON struct {
	Data string `json:"data"`
}

func main() {

	certpool := x509.NewCertPool()

	file_b, err := os.ReadFile("certs/ca.pem")

	certpool.AppendCertsFromPEM(file_b)

	tlsConfig := &tls.Config{
		RootCAs: certpool,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	req := CommJSON{
		Data: "hello",
	}

	respjson := CommJSON{}

	jb, err := json.Marshal(req)

	if err != nil {
		log.Println(err)
		return
	}

	r, err := http.NewRequest("POST", "https://localhost:8888/hello", bytes.NewBuffer(jb))

	if err != nil {
		log.Println(err)
		return
	}

	r.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(r)

	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()

	log.Printf("is HTTP 1: %v (%s)\n\n", resp.ProtoAtLeast(1, 0), resp.Proto)

	derr := json.NewDecoder(resp.Body).Decode(&respjson)

	if derr != nil {
		log.Println(err)
		return

	}

	log.Printf("server data: %s\n", respjson.Data)

}
