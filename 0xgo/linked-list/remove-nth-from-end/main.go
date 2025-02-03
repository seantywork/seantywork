package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	pkgutil "github.com/seantywork/0xgo/util"
)

type ListNode struct {
	Val  int
	Next *ListNode
}

func removeNthFromEnd(head *ListNode, n int) *ListNode {

	nodes := make([]*ListNode, 0)

	ans := new(ListNode)

	for {

		if head.Next != nil {

			nodes = append(nodes, head)

			head = head.Next

		} else {

			nodes = append(nodes, head)

			break
		}
	}

	nlen := len(nodes)

	exclude := nlen - n

	if nlen == 1 {

		ans = nil

	} else {

		if exclude == (nlen - 1) {

			nodes[exclude-1].Next = nil

			ans = nodes[0]

		} else if exclude-1 < 0 {

			ans = nodes[exclude+1]

		} else {

			nodes[exclude-1].Next = nodes[exclude+1]

			ans = nodes[0]
		}

	}

	return ans

}

func main() {

	var T int

	reader := bufio.NewReader(os.Stdin)

	t, err := reader.ReadString('\n')

	if err != nil {

		log.Printf("failed to read string\n")

		return
	}

	fmt.Sscanf(t, "%d", &T)

	for i := 0; i < T; i++ {

		var n int = 0

		l, err := reader.ReadString('\n')

		if err != nil {

			log.Printf("failed to read line\n")

			return
		}

		nstr, err := reader.ReadString('\n')

		if err != nil {

			log.Printf("failed to read line\n")

			return
		}

		ll := pkgutil.SanitizeUnnecessary(l)

		nn := pkgutil.SanitizeUnnecessary(nstr)

		els := strings.Split(ll, " ")

		ellen := len(els)

		fmt.Sscanf(nn, "%d", &n)

		lns := []ListNode{}

		for j := 0; j < ellen; j++ {

			val := 0

			fmt.Sscanf(els[j], "%d", &val)

			ln := ListNode{
				Val:  val,
				Next: nil,
			}

			lns = append(lns, ln)
		}

		for j := 0; j < ellen-1; j++ {

			lns[j].Next = &lns[j+1]

		}

		ans := removeNthFromEnd(&lns[0], n)

		for {

			if ans == nil {
				fmt.Printf(" \n")
				break
			}
			fmt.Printf("%d ", ans.Val)

			if ans.Next != nil {
				ans = ans.Next
			} else {
				fmt.Printf("\n")
				break
			}
		}

	}

}
