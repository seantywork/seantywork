package main

import (
	"fmt"
	"net"
	"os"
)

func main() {

	mode := os.Args[1]

	if mode == "net" {
		ln, err := net.Listen("tcp", "0.0.0.0:8080")
		if err != nil {
			fmt.Println(err)
			return
		}

		for {
			conn, err := ln.Accept()
			if err != nil {
				fmt.Println(err)
				continue
			}

			rc := make(chan []byte, 1024)

			wc := make(chan []byte, 1024)

			go readHandler(conn, rc)

			go worker(rc, wc)

			go writeHandler(conn, wc)

		}
	} else if mode == "tls" {

		TlsListen()

	}

}

func readHandler(c net.Conn, rc chan []byte) {

	buf := make([]byte, 1024)

	for {

		readlen := 0

		for readlen != 1024 {

			n, err := c.Read(buf[readlen:])
			if err != nil {
				fmt.Println(err)
				return
			}

			readlen += n
		}

		fmt.Printf("Received len: %d\n", readlen)

		rc <- buf

	}

}

func worker(rc chan []byte, wc chan []byte) {

	for {

		rbuf := <-rc

		fmt.Printf("Worker: %s\n", string(rbuf))

		wc <- rbuf

	}

}

func writeHandler(c net.Conn, wc chan []byte) {

	for {

		wbuf := <-wc

		n, err := c.Write(wbuf)

		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Printf("Write len: %d\n", n)

	}

}
