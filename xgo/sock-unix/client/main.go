package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

var addr = "/tmp/this.sock"

func GetClient(baseAddr string) (net.Conn, error) {

	c, err := net.Dial("unix", baseAddr)

	if err != nil {

		return nil, fmt.Errorf("failed to set ipc client: %s", err.Error())
	}

	return c, nil
}

func main() {

	c, err := GetClient(addr)

	if err != nil {

		log.Printf("failed: %s\n", err.Error())

		return
	}

	buff := make([]byte, 512)

	copy(buff, "hello world")

	for {

		time.Sleep(1 * time.Second)

		n, err := c.Write(buff)

		if err != nil {

			log.Printf("write failed: %s\n", err.Error())

			break
		}

		_ = n

		buff := make([]byte, 512)

		n, err = c.Read(buff)

		if err != nil {

			log.Printf("read failed: %s\n", err.Error())

			break

		}

		log.Printf("got message\n")

		fmt.Println(string(buff))

	}

}
