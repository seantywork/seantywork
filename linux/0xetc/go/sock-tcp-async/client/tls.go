package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"
)

func TlsConnection() {

	certpool := x509.NewCertPool()

	file_b, err := os.ReadFile("certs/ca.pem")

	/*
		ca_pem := new(bytes.Buffer)

		pem.Encode(ca_pem, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: file_b,
		})
	*/
	certpool.AppendCertsFromPEM(file_b)

	config := tls.Config{RootCAs: certpool}
	conn, err := tls.Dial("tcp", "localhost:8080", &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
		fmt.Println(v.Subject)
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
	wbuf := make([]byte, 1024)

	copy(wbuf, "Hello, tls server!")
	n, err := conn.Write(wbuf)
	if err != nil {
		log.Fatalf("client: write: %s", err)
	}

	reply := make([]byte, 1024)

	readlen := 0

	for readlen != 1024 {

		n, err = conn.Read(reply[readlen:])
		if err != nil {
			fmt.Println(err)
			return
		}

		readlen += n
	}

	log.Printf("client: read :%s (%d bytes)", string(reply[:readlen]), readlen)
	time.Sleep(time.Millisecond * 1000)
	log.Print("client: exiting")
}
