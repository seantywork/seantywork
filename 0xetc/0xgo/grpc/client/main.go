package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"log"
	"os"
	"time"

	pb "feebdaed.xyz/git/linuxyz.git/0xetc/0xgo/grpc/chatpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defaultName = "world"
)

var (
	addr = flag.String("addr", "localhost:50051", "the address to connect to")
	name = flag.String("name", defaultName, "Name to greet")
)

func main() {
	flag.Parse()

	pemServerCA, err := os.ReadFile("certs/ca.pem")
	if err != nil {
		log.Fatalf("failed to load cert")
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		log.Fatalf("failed to add server CA's certificate")
	}

	config := &tls.Config{
		RootCAs: certPool,
	}

	newTLSconfig := credentials.NewTLS(config)

	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(newTLSconfig))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewChatterClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	r, err := c.SayHello(ctx, &pb.HelloRequest{Name: *name})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	my_id := r.GetMessage()

	log.Printf("Greeting: %s", r.GetMessage())

	r_stream, err := c.TalkToMe(ctx, &pb.TalkRequest{Message: my_id})

	if err != nil {
		log.Fatalf("could not get to talk to: %v", err)
	}

	done := make(chan bool)

	recent_id := 0

	go func() {
		for {
			resp, err := r_stream.Recv()
			if err == io.EOF {
				done <- true
				return
			}
			if err != nil {
				log.Fatalf("cannot receive %v", err)
			}

			tc := resp.GetTalkContent()

			recent_id = int(tc.GetIndex())

			log.Printf("Resp received: %s", tc.GetContent())
		}
	}()

	<-done

	r2, err := c.WhatDidYouSay(ctx, &pb.HistoryRequest{Index: int64(recent_id)})

	if err != nil {
		log.Fatalf("could not ask: %v", err)
	}

	it_said := r2.GetHistory()

	for i := 0; i < len(it_said); i++ {

		at := it_said[i].GetIndex()

		word := it_said[i].GetContent()

		log.Printf("it said [%d]: %s", at, word)

	}

}
