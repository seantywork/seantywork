package main

import (
	"log"

	etcqcore "github.com/seantywork/etc/go/etcd-query/core"
)

func main() {

	cli, err := etcqcore.ConnectEtcd()

	defer cli.Close()

	if err != nil {

		log.Fatalln(err.Error())
	}

	test_key := "my_little_key"

	test_val := "myLittleValue"

	err = etcqcore.PutKey(cli, test_key, test_val)

	if err != nil {
		log.Fatalln(err.Error())
	}

	err = etcqcore.GetKey(cli, test_key)

	if err != nil {
		log.Fatalln(err.Error())
	}

}
