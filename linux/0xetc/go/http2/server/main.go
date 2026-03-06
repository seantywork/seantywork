package main

import (
	"log"
	"net/http"

	"golang.org/x/net/http2"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {

	w.Write([]byte("hello"))
}

func main() {

	http.HandleFunc("/hello", helloHandler)

	var srv http.Server
	srv.Addr = "0.0.0.0:8888"
	http2.ConfigureServer(&srv, &http2.Server{})

	err := srv.ListenAndServeTLS("certs/server.pem", "certs/server.key")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
