package main

import (
	"fmt"
	"net"
)

var addr = "0.0.0.0:8888"

func main() {

	p := make([]byte, 128)
	conn, err := net.Dial("udp", addr)

	if err != nil {
		fmt.Printf("Some error %v", err)
		return
	}

	copy(p, "hello udp server")

	n, err := conn.Write(p)

	if err == nil {
		fmt.Printf("sent %d\n", n)
	} else {
		fmt.Printf("Some error %v\n", err)
	}
	conn.Close()
}
