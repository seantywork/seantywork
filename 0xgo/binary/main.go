package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

func main() {

	var i uint32 = 0x0100
	ptr := unsafe.Pointer(&i)
	if 0x01 == *(*byte)(ptr) {
		fmt.Println("Big Endian")
	} else if 0x00 == *(*byte)(ptr) {
		fmt.Println("Little Endian")
	}

	ipstring := "10.1.10.2"

	ipbytes := net.ParseIP(ipstring).To4()

	fmt.Println(ipbytes)

	testle := binary.LittleEndian.Uint32(ipbytes)

	testbe := binary.BigEndian.Uint32(ipbytes)

	testne := binary.NativeEndian.Uint32(ipbytes)

	fmt.Printf("le: %d, be: %d, ne: %d\n", testle, testbe, testne)

	lebytes := make([]byte, 4)
	bebytes := make([]byte, 4)
	nebytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(lebytes, testle)

	binary.BigEndian.PutUint32(bebytes, testbe)

	binary.NativeEndian.PutUint32(nebytes, testne)

	fmt.Printf("%d %d %d %d\n", lebytes[0], lebytes[1], lebytes[2], lebytes[3])

	fmt.Printf("%d %d %d %d\n", bebytes[0], bebytes[1], bebytes[2], bebytes[3])

	fmt.Printf("%d %d %d %d\n", nebytes[0], nebytes[1], nebytes[2], nebytes[3])

	testle = binary.LittleEndian.Uint32(lebytes)

	testbe = binary.BigEndian.Uint32(bebytes)

	testne = binary.NativeEndian.Uint32(nebytes)

	fmt.Printf("le: %d, be: %d, ne: %d\n", testle, testbe, testne)

	fmt.Println("ntohl")

	in := testbe

	fmt.Printf("in: %d\n", in)

	tmp := make([]byte, 4)

	binary.BigEndian.PutUint32(tmp, in)

	out := binary.LittleEndian.Uint32(tmp)

	fmt.Printf("out: %d\n", out)

	fmt.Println("htonl")

	in = out

	fmt.Printf("in: %d\n", in)

	tmp = make([]byte, 4)

	binary.LittleEndian.PutUint32(tmp, in)

	out = binary.BigEndian.Uint32(tmp)

	fmt.Printf("out: %d\n", out)

}
