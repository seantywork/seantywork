package core

import (
	"context"
	"log"
	"strconv"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func ConnectEtcd() (*clientv3.Client, error) {

	_, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2379"},
		DialTimeout: 2 * time.Second,
	})

	if err == context.DeadlineExceeded {
		log.Println("deadline execeeded")
		return nil, err
	}

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2379"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Println("failed to get new clien")
		return nil, err
	}

	log.Println("connection success!")

	return cli, nil

}

func PutKey(cli *clientv3.Client, key string, val string) error {

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*1000*10)

	_, err := cli.Put(ctx, key, val)

	cancel()

	if err != nil {

		return err

	}

	log.Println("put successful")

	return nil
}

func GetKey(cli *clientv3.Client, key string) error {

	resp, err := cli.Get(context.TODO(), key)

	if err != nil {
		log.Println("failed to get")
		return err
	}

	match_len := len(resp.Kvs)

	match_len_str := strconv.Itoa(match_len)

	log.Println("matched count: " + match_len_str)

	log.Println("match: key: " + string(resp.Kvs[0].Key) + " val: " + string(resp.Kvs[0].Value))

	return nil

}
