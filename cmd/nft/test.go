package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"

	"github.com/alex60217101990/packets-dump/internal/nftables"
	"github.com/alex60217101990/types/enums"
	"golang.org/x/sys/unix"
)

var toPort = flag.Int("to", 0, "Proxy to port number")
var fromPort = flag.Int("from", 0, "Proxy from port number")
var dump = flag.Bool("dump", false, "Dump nftables ruleset")
var close = flag.Bool("close", false, "Clear all tables")
var arg enums.NftActionType

func main() {
	flag.Var(&arg, "action", "Type of nft action")
	flag.Parse()
	var nft *nftables.NftablesService
	if *close {
		nft = nftables.NewNftService()
		log.Println(nft.Close())
	}
	if *dump {
		nftables.DumpRulesetList()
		return
	}
	fmt.Printf("action: %v, %d => %d\n", arg, *fromPort, *toPort)
	if *toPort == 0 || *fromPort == 0 {
		log.Fatal("invalid one of ports parameter")
	}
	runtime.LockOSThread()
	// nftables.NewNftService()
	nft = nftables.NewNftService()
	log.Println(nft.ChangeLocalProxyRule(arg, "proxyIPv4", uint16(*fromPort), uint16(*toPort), unix.IPPROTO_TCP))
}
