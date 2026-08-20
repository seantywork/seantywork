package main

import (
	"fmt"
	"log"
	"net"
)

var addr = "/tmp/this.sock"

func GetServer(baseAddr string) (net.Listener, error) {

	listener, err := net.Listen("unix", baseAddr)

	if err != nil {

		return nil, fmt.Errorf("listen error: %s", err.Error())

	}

	return listener, nil
}

func doProcess(c net.Conn) {

	for {

		buf := make([]byte, 512)

		wbuf := make([]byte, 512)

		n, err := c.Read(buf)

		if err != nil {

			log.Printf("read: %s\n", err.Error())

			return
		}

		nStr := fmt.Sprintf("%d", n)

		var strlen int = 0

		for i := 0; i < 512; i++ {

			strlen = i

			if buf[i] == 0 {

				break
			}

		}

		copy(wbuf, buf[:strlen])

		copy(wbuf[strlen:], []byte(nStr))

		_, err = c.Write(wbuf)

		if err != nil {

			log.Printf("write: %s\n", err.Error())

			return
		}

	}

}

func main() {

	l, err := GetServer(addr)

	if err != nil {
		log.Printf("failed to get server: %s\n", err.Error())

		return
	}

	for {

		c, err := l.Accept()

		if err != nil {

			log.Printf("failed to accept: %s\n", err.Error())

			continue
		}

		go doProcess(c)

	}

}
