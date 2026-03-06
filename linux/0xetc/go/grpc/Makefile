

all:

	@echo "go grpc"


dep:

	apt install -y protobuf-compiler

dep-go: 

	go install google.golang.org/protobuf/cmd/protoc-gen-go

	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc

proto:

	cd chatpb && ./protoc.sh

build:

	go build -o server/server.out ./server 

	go build -o client/client.out ./client 





