package main

/*
#cgo CFLAGS: -g -Wall -I../../go-c-lib/c2go
#cgo LDFLAGS: -L../../go-c-lib/c2go -Wl,-rpath=../../go-c-lib/c2go -lc2go
#include "c2go.h"
*/
import "C"
import (
	"fmt"
)

type (
	Person C.struct_APerson
)

func (p *Person) Name() string {
	return C.GoString(p.name)
}

func (p *Person) LongName() string {
	return C.GoString(p.long_name)
}

func GetPerson(name string, long_name string) *Person {
	return (*Person)(C.get_person(C.CString(name), C.CString(long_name)))
}

func main() {
	var f *Person
	f = GetPerson("seanty", "work")
	fmt.Printf("Hello Go world: My name is %s, %s.\n", C.GoString(f.name), C.GoString(f.long_name))

	fmt.Printf("Hello Go world: My name is %s, %s.\n", f.Name(), f.LongName())
}
