package main

import (
	"log"

	"golang.org/x/sys/unix"

	"github.com/alex60217101990/packets-dump/internal/nftables"
)



func main() {
	nft := nftables.NewNftService()
	log.Println(nft.AddLocalProxyRule("proxyIPv4", 4422, 9933, unix.IPPROTO_TCP))
}
