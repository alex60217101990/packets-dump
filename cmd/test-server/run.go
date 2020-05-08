package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

var port = flag.Int("port", 0, "Server port")

func main() {
	flag.Parse()
	if *port <= 0 {
		log.Fatal("-port is required.")
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK!")
	})
	http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
}
