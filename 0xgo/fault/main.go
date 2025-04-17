package main

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

var TLEN = 10

func busy() {

	val := 1
	str := ""
	for {

		str = fmt.Sprintf("%d", val)

		_ = str
	}

}

func notbusy(idx int) {

	val := 1
	str := ""
	for {

		time.Sleep(time.Millisecond * 1)

		str = fmt.Sprintf("%d", val)

		fmt.Printf("i'm not busy: %d: %s\n", idx, str)

	}
}

func threadFunc() {

	for i := 0; i < TLEN; i++ {

		if i == 5 {

			go busy()

		} else {

			go notbusy(i)

		}

	}

}

func profiler(waits int) {

	runtime.GC()

	cpuProfileBuff := &bytes.Buffer{}

	err := pprof.StartCPUProfile(cpuProfileBuff)

	if err != nil {

		panic(err)
	}

	time.Sleep(time.Second * time.Duration(waits))

	pprof.StopCPUProfile()

	runtime.GC()

	profileBytes := cpuProfileBuff.Bytes()

	f, err := os.OpenFile("go.prof", os.O_CREATE|os.O_RDWR, 0644)

	if err != nil {

		panic(err)
	}

	f.Write(profileBytes)

	f.Close()

}

func main() {

	go threadFunc()

	go profiler(10)

	for {

		time.Sleep(time.Millisecond * 1000)

	}

}
