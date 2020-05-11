package main

import (
	"crypto/tls"
	"flag"
	"net/http"
	"net/url"

	"log"
)

var (
	proxy  = flag.String("proxy", "", "proxy address for test request")
	server = flag.String("s", "http://127.0.0.1", "server address")
)

func main() {
	flag.Parse()
	url_i := url.URL{}
	url_proxy, _ := url_i.Parse(*proxy)

	transport := &http.Transport{}
	transport.Proxy = http.ProxyURL(url_proxy)                        // set proxy
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl

	client := &http.Client{}
	client.Transport = transport
	resp, err := client.Get(*server)
	log.Println(resp, err)
}
