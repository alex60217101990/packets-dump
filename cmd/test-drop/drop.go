package main

import (
	"flag"
	"log"
	"os"
	"os/signal"

	//"github.com/dropbox/goebpf"
	"github.com/alex60217101990/goebpf"
	"github.com/alex60217101990/types/models"
)

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "./fw.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "xdp_fw", "Name of XDP program (function name)")

const (
	// Size of structure used to pass metadata
	metadataSize = 4
)

func main() {
	flag.Parse()
	if *iface == "" {
		log.Fatal("-iface is required.")
	}

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Create eBPF system / load .ELF files compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		log.Fatal("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	// Program name matches function name in xdp.c:
	//      int xdp_dump(struct xdp_md *ctx)
	xdp := bpf.GetProgramByName(*programName)
	if xdp == nil {
		log.Fatal("Program '%s' not found. ", *programName)
	}

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

	// Find special "PERF_EVENT" eBPF map
	// portsTCPMap := bpf.GetMapByName("ports_tcp")
	// if portsTCPMap == nil {
	// 	log.Fatal("eBPF map 'ports_tcp_h' not found")
	// }

	// err = portsTCPMap.Upsert(models.PortKey{
	// 	Type:  enums.SourcePort,
	// 	Proto: enums.TCP,
	// 	Port:  3128,
	// }, 1)
	// if err != nil {
	// 	log.Println(err)
	// }
	// err = portsTCPMap.Upsert(models.PortKey{
	// 	Type:  enums.DestinationPort,
	// 	Proto: enums.TCP,
	// 	Port:  3128,
	// }, 2)
	// if err != nil {
	// 	log.Println(err)
	// }
	// err = portsTCPMap.Upsert(models.PortKey{
	// 	Type:  enums.SourcePort,
	// 	Proto: enums.TCP,
	// 	Port:  5555,
	// }, 3)
	// if err != nil {
	// 	log.Println(err)
	// }
	// err = portsTCPMap.Upsert(models.PortKey{
	// 	Type:  enums.DestinationPort,
	// 	Proto: enums.TCP,
	// 	Port:  5555,
	// }, 4)
	// if err != nil {
	// 	log.Println(err)
	// }

	// macBlacklist := bpf.GetMapByName("mac_blacklist")
	// if macBlacklist == nil {
	// 	log.Println("eBPF map 'mac_blacklist' not found")
	// 	os.Exit(1)
	// }
	// addr, err := net.ParseMAC("00:00:5e:00:53:01" /*"00:00:00:00:00:00"*/)
	// if macBlacklist == nil {
	// 	log.Fatal("eBPF map 'mac_blacklist' not found")
	// 	log.Println("parse MAC error:", err)
	// 	os.Exit(1)
	// }
	// err = macBlacklist.Upsert(addr, 1)
	// if err != nil {
	// 	log.Println(err)
	// 	os.Exit(1)
	// }

	ipv4Blacklist := bpf.GetMapByName("v4_blacklist")
	if ipv4Blacklist == nil {
		log.Println("eBPF map 'v4_blacklist' not found")
		os.Exit(1)
	}
	var ipv4 models.IPv4Key
	err = ipv4.ParseFromStr("127.0.0.1")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	err = ipv4Blacklist.Upsert(&ipv4, 1)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	ipv6Blacklist := bpf.GetMapByName("v6_blacklist")
	if ipv6Blacklist == nil {
		log.Println("eBPF map 'v6_blacklist' not found")
		os.Exit(1)
	}
	var ipv6 models.IPv6Key
	err = ipv6.ParseFromStr("::1")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	err = ipv6Blacklist.Upsert(&ipv6, 1)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	defer func() {
		if r := recover(); r != nil {
			log.Println("panic", r)
		}
		xdp.Detach()
	}()

	log.Println("XDP program successfully loaded and attached.")
	log.Println("All new TCP connection requests (SYN) coming to this host will be dumped here.")
	log.Println()

	// Wait until Ctrl+C pressed
	<-ctrlC

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
