package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/alex60217101990/packets-dump/internal/iptables"
	"github.com/alex60217101990/types/enums"
)

var arg enums.NftActionType

func main() {
	flag.Var(&arg, "action", "Type of nft action")
	flag.Parse()

	ch := make(chan struct{})
	iptables.Pps(ch, "wlp9s0")
	<-time.After(15 * time.Second)
	close(ch)

	os.Exit(0)
	switch arg {
	case enums.AddAction:
		iptables.AddForwardRule()
	case enums.DeleteAction:
		iptables.DelForwardRule()
	default:
		log.Fatal("invalid action")
	}
}
