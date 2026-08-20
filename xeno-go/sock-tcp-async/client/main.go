package main

import (
	"fmt"
	"net"
	"os"
)

func main() {

	mode := os.Args[1]

	if mode == "net" {
		conn, err := net.Dial("tcp", "localhost:8080")
		if err != nil {
			fmt.Println(err)
			return
		}

		wbuf := make([]byte, 1024)

		copy(wbuf, "Hello, server!")

		_, err = conn.Write(wbuf)
		if err != nil {
			fmt.Println(err)
			return
		}

		conn.Close()

	} else if mode == "tls" {

		TlsConnection()
	}

}
