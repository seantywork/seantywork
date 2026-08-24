package main

import (
	"fmt"
	"time"
)

func main() {

	sig := make(chan int)
	sig2 := make(chan int)

	go func() {

		time.Sleep(3 * time.Second)

		sig <- 1
	}()

	go func() {
		time.Sleep(3 * time.Second)

		sig2 <- 1
	}()

	for {

		fmt.Println("loop...")
		select {
		case <-sig:
			fmt.Println("got sig 1")
			return
		case <-sig2:
			fmt.Println("got sig 2")
			return
		}

	}
}
