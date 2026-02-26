package main

import (
	"context"
	"fmt"
	"time"
)

var TIMEOUTSEC int = 10

func main() {

	ctx := context.Background()

	if d, ok := ctx.Deadline(); ok {
		fmt.Printf("yes deadline: %v\n", d)
	} else {
		fmt.Printf("no deadline\n")
	}

	ctxTimeOut, cancel := context.WithTimeout(ctx, time.Millisecond*1000*time.Duration(TIMEOUTSEC))

	if d, ok := ctxTimeOut.Deadline(); ok {
		fmt.Printf("yes deadline: %v\n", d)
	} else {
		fmt.Printf("no deadline\n")
	}

	go func() {
		time.Sleep(time.Millisecond * 5000)
		fmt.Println("<< calling cancel")
		cancel()
	}()

	for {
		select {
		case <-ctxTimeOut.Done():
			fmt.Println("timeout")
			return
		default:
			fmt.Println("waiting...")
			time.Sleep(time.Second * 1)
		}
	}
}
