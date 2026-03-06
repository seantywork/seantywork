package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type CommJSON struct {
	Data string `json:"data"`
}

func clientHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("client access")

	u := websocket.Upgrader{}

	u.CheckOrigin = func(r *http.Request) bool { return true }

	c, err := u.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("client upgrade: %s\n", err.Error())
		return
	}

	c.SetReadDeadline(time.Time{})

	defer c.Close()

	log.Printf("client accepted")

	for {

		req := CommJSON{}

		resp := CommJSON{}

		err := c.ReadJSON(&req)

		if err != nil {

			log.Printf("client handle: client gone")

			_ = c.Close()

			return

		}

		log.Printf("client data: %s\n", req.Data)

		resp.Data = req.Data

		err = c.WriteJSON(resp)

		if err != nil {

			log.Printf("failed to write: %s", err.Error())

			_ = c.Close()

			return
		}

	}

}

func run() error {

	http.HandleFunc("/hello", clientHandler)

	log.Fatal(http.ListenAndServeTLS("0.0.0.0:8888", "certs/server.pem", "certs/server.key", nil))

	return nil
}

func main() {

	if err := run(); err != nil {

		log.Fatal(err.Error())
	}

}
