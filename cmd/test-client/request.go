package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"log"
)

var (
	proxy  = flag.String("proxy", "", "proxy address for test request")
	server = flag.String("s", "http://127.0.0.1", "server address")
	ipv6   = flag.Bool("ipv6", false, "use ipv6 transport")
)

func main() {
	flag.Parse()
	if *ipv6 {
		conn, err := net.Dial("tcp6", *server)
		defer func() {
			if conn != nil {
				conn.Close()
			}
		}()
		if err != nil {
			log.Println(err)
			return
		}
		s := func() <-chan []byte {
			send := make(chan []byte)
			data := make([]byte, 512)
			go func() {
				defer close(send)
				for {
					conn.Read(data)
					send <- data
					return
				}
			}()
			return send
		}()
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
		log.Println(string(<-s))
	} else {
		transport := &http.Transport{}
		if len(*proxy) > 0 {
			url_i := url.URL{}
			url_proxy, _ := url_i.Parse(*proxy)

			transport.Proxy = http.ProxyURL(url_proxy)                        // set proxy
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl
		}
		client := &http.Client{}
		client.Transport = transport
		resp, err := client.Get(*server)
		log.Println(resp, err)
	}
}
