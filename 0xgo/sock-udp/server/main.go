package main

import (
	"fmt"
	"log"
	"net"
	"strings"
)

var addr = "0.0.0.0:8888"

func GetServer(addr string) (*net.UDPConn, error) {

	addrlist := strings.Split(addr, ":")

	var port int

	fmt.Sscanf(addrlist[1], "%d", &port)

	ip := net.ParseIP(addrlist[0]).To4()

	udpaddr := net.UDPAddr{

		IP:   ip,
		Port: port,
	}

	listener, err := net.ListenUDP("udp", &udpaddr)

	if err != nil {

		return nil, fmt.Errorf("failed to get server: %s", err.Error())
	}

	return listener, nil
}

func main() {

	l, err := GetServer(addr)

	if err != nil {

		log.Printf("failed: %s\n", err.Error())

		return
	}

	for {

		buf := make([]byte, 128)

		_, remoteaddr, err := l.ReadFromUDP(buf)

		strbuf := string(buf)

		fmt.Printf("Read a message from %v: %s\n", remoteaddr, strbuf)

		if err != nil {
			fmt.Printf("Some error  %v", err)
			continue
		}

	}
}
