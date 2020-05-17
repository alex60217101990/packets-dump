package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

var port = flag.Int("port", 0, "Server port")
var useV6 = flag.Bool("v6", false, "use ipv6 transport")

func baseHandle(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK!")
}

func main() {
	flag.Parse()
	if *port <= 0 {
		log.Fatal("-port is required.")
	}
	http.HandleFunc("/", baseHandle)
	if *useV6 {
		mux := http.NewServeMux()
		// Convert the timeHandler function to a HandlerFunc type
		th := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "OK!")
		})
		mux.Handle("/", th)
		ListenAndServe(fmt.Sprintf(":%d", *port), mux)
	} else {
		http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
	}
}

func ListenAndServe(addr string, handler http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: handler}
	addr = srv.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp6", addr) // <--- tcp6 here
	if err != nil {
		return err
	}
	return srv.Serve(ln.(*net.TCPListener))
}
