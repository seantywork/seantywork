package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	pb "github.com/seantywork/etc/go/grpc/chatpb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var allowed_names []string

var user_idx int = 0

var loop_idx int = 0

var word_idx int = 0

var words = []string{
	"hello",
	"my",
	"name",
	"is",
	"test",
	"program",
}

var history pb.HistoryResponse

var (
	port = flag.Int("port", 50051, "The server port")
)

type server struct {
	pb.UnimplementedChatterServer
}

func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())

	allowing := in.GetName() + "-" + strconv.FormatInt(int64(user_idx), 10)

	user_idx += 1

	allowed_names = append(allowed_names, allowing)

	return &pb.HelloReply{Message: allowing}, nil
}

func (s *server) TalkToMe(in *pb.TalkRequest, srv pb.Chatter_TalkToMeServer) error {

	log.Printf("Received: %v", "talk")

	if len(allowed_names) == 0 {

		return fmt.Errorf("no allowed user")
	}

	hit := 0
	name := ""

	for i := 0; i < len(allowed_names); i++ {

		name = in.GetMessage()

		if name == allowed_names[i] {

			log.Printf("found: %v", name)

			hit = 1

			break

		}

	}

	if hit != 1 {

		return fmt.Errorf("failed to retrieve user")

	}

	max_idx := len(words) - 1

	for {

		if loop_idx > max_idx {

			loop_idx = 0

			break

		}

		tc := pb.TalkContent{
			Index:   int64(word_idx),
			Content: words[word_idx],
		}

		history.History = append(history.History, &tc)

		resp := pb.TalkResponse{
			TalkContent: &tc,
		}

		if err := srv.Send(&resp); err != nil {

			log.Printf("send error %v", err)

		}

		loop_idx += 1

		word_idx += 1

		time.Sleep(time.Second * 1)

	}

	return nil
}

func (s *server) WhatDidYouSay(ctx context.Context, in *pb.HistoryRequest) (*pb.HistoryResponse, error) {

	log.Printf("Received: %v", in.GetIndex())

	if len(history.History) < 3 {

		null_array := []*pb.TalkContent{}

		hr := pb.HistoryResponse{
			History: null_array,
		}

		return &hr, fmt.Errorf("not enough has been said")

	}

	idx_from := in.GetIndex()

	i := 0

	resp_array := []*pb.TalkContent{}

	for {

		if i > 2 {
			break
		}

		target_idx := int(idx_from) - i

		history_el := history.History[target_idx]

		resp_array = append(resp_array, history_el)

		i += 1
	}

	resp := pb.HistoryResponse{
		History: resp_array,
	}

	return &resp, nil
}

func main() {
	flag.Parse()

	serverCert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server.key")
	if err != nil {
		log.Fatalf("failed to load cert and key")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	newTLSconfig := credentials.NewTLS(config)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(
		grpc.Creds(newTLSconfig),
	)

	pb.RegisterChatterServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
