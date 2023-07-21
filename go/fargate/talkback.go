package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type TeenageHeart struct {
	Name    string `json:"name"`
	Comment string `json:"comment"`
}

func Talkback(w http.ResponseWriter, r *http.Request) {

	var th TeenageHeart

	th.Name = "what do you want my name for?"

	th.Comment = "get the hell off"

	ret_b, err := json.Marshal(th)

	if err != nil {

		w.Header().Set("Content-Type", "text/plain")

		w.WriteHeader(http.StatusInternalServerError)

		w.Write([]byte(err.Error()))

		return
	}

	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)

	w.Write(ret_b)

}

func main() {

	http.HandleFunc("/talkback", Talkback)

	log.Fatal(http.ListenAndServe("0.0.0.0:8888", nil))
}
