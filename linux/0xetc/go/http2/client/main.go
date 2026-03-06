package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/net/http2"
)

func main() {

	certpool := x509.NewCertPool()

	file_b, err := os.ReadFile("certs/ca.pem")

	certpool.AppendCertsFromPEM(file_b)

	tlsConfig := &tls.Config{
		RootCAs: certpool,
	}

	transport := &http2.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://localhost:8888/hello")

	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("is HTTP2: %v (%s)\n\n", resp.ProtoAtLeast(2, 0), resp.Proto)

	io.Copy(os.Stdout, resp.Body)
}
