package iptables

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
)

func AddForwardRule() {
	ipt, err := iptables.New()
	table := "nat"
	iface := "eth0"
	// put a simple rule in
	err = ipt.Append(table, chain, "-s", "0/0", "-j", "ACCEPT")
	if err != nil {
		fmt.Printf("Append failed: %v", err)
	}
}
