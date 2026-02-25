package main

import (
	"context"
	"fmt"
)

func main() {

	ctx := context.Background()

	if d, ok := ctx.Deadline(); ok {
		fmt.Printf("yes deadlin: %v\n", d)
	} else {
		fmt.Printf("no deadline\n")
	}

}
