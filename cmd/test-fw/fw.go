package main

import (
	"flag"
	"log"

	"github.com/alex60217101990/packets-dump/internal/fw"
	"github.com/alex60217101990/packets-dump/internal/models"
	"github.com/dropbox/goebpf"
)

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "./fw.elf", "clang/llvm compiled binary file")
var addr = flag.String("addr", "", "Address for test ip functions")
var programName = flag.String("program", "xdp_fw", "Name of XDP program (function name)")

func main() {
	flag.Parse()
	if *iface == "" {
		log.Fatal("-iface is required.")
	}

	// Create eBPF system / load .ELF files compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		log.Fatal("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	// Get eBPF maps
	macBlacklist := bpf.GetMapByName("mac_blacklist")
	if macBlacklist == nil {
		log.Fatal("eBPF map 'mac_blacklist' not found")
	}
	iv4Blacklist := bpf.GetMapByName("v4_blacklist")
	if iv4Blacklist == nil {
		log.Fatal("eBPF map 'v4_blacklist' not found")
	}
	iv6Blacklist := bpf.GetMapByName("v6_blacklist")
	if iv6Blacklist == nil {
		log.Fatal("eBPF map 'v6_blacklist' not found")
	}
	portBlacklist := bpf.GetMapByName("port_blacklist")
	if iv6Blacklist == nil {
		log.Fatal("eBPF map 'port_blacklist' not found")
	}

	// Program name matches function name in xdp_fw.c:
	xdp := bpf.GetProgramByName(*programName)
	if xdp == nil {
		log.Fatalf("Program '%s' not found.", "xdp_fw")
	}

	var lpmV6 models.LpmV6Key
	log.Println(lpmV6.ParseFromSrt(*addr))
	log.Println(fw.Firewall{})

	// var ipnet *net.IPNet
	// err := iv4Blacklist.Insert(goebpf.CreateLPMtrieKey(ip), index)

	// Load XDP program into kernel
	err = xdp.Load()
	if err != nil {
		log.Fatal("xdp.Load(): %v", err)
	}

	// Attach to interface
	err = xdp.Attach(*iface)
	if err != nil {
		log.Fatal("xdp.Attach(): %v", err)
	}
	defer func() {
		if r := recover(); r != nil {
			log.Println("panic", r)
		}
		xdp.Detach()
		portBlacklist.Close()
		iv6Blacklist.Close()
		iv4Blacklist.Close()
		macBlacklist.Close()
	}()

	// Stop perf events and print summary
	log.Println("\nDetaching program and exit...")
}

func printBpfInfo(bpf goebpf.System) {
	log.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		m := item.(*goebpf.EbpfMap)
		log.Printf("\t%s: %v, Fd %v\n", m.Name, m.Type, m.GetFd())
	}
	log.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		log.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	log.Println()
}
