package main

import (
	"fmt"
	"time"
	"unsafe"
)

const TESTCASE = 1000000
const BUFFSIZE = 2048

var THEN time.Time
var NOW time.Time

type testdata struct {
	top    uint32
	bottom uint32
}

func do_enqueue(tdch chan testdata) {
	var td testdata = testdata{}
	THEN = time.Now()
	for i := 0; i < TESTCASE; i++ {
		td.top = uint32(i + 1)
		td.bottom = uint32(i - 1)
		tdch <- td
	}
}

func do_dequeue(tdch chan testdata) error {
	var counter = 0
	for counter < TESTCASE {
		td := <-tdch
		if td.top != uint32(counter+1) {
			return fmt.Errorf("invalid top value: %d != %d\n", td.top, uint32(counter+1))
		}
		if td.bottom != uint32(counter-1) {
			return fmt.Errorf("invalid bottom value: %d != %d\n", td.top, uint32(counter-1))
		}
		counter += 1
	}
	NOW = time.Now()
	return nil
}

func main() {
	td := testdata{}
	tdchan := make(chan testdata, BUFFSIZE)
	go do_enqueue(tdchan)
	if err := do_dequeue(tdchan); err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	lapsed_ms := NOW.Sub(THEN).Milliseconds()
	fmt.Printf("%d-entry, sized %d-byte, took %dms\n", TESTCASE, unsafe.Sizeof(td), lapsed_ms)
	return
}
