package main

import (
	"log"

	"github.com/milosgajdos/tenus"
)

func main() {
	// RETRIEVE EXISTING INTERFACE
	dl, err := tenus.NewLinkFrom("eth0")
	if err != nil {
		log.Fatal(err)
	}
	
}
