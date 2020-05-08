package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
	"github.com/dropbox/goebpf"
)

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "./dump.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "xdp_dump", "Name of XDP program (function name)")

const (
	// Size of structure used to pass metadata
	metadataSize = 4
)

func main() {
	flag.Parse()
	if *iface == "" {
		log.Fatal("-iface is required.")
	}
	_, err := netlink.LinkByName(*iface)
	if err != nil {
		log.Println("Linked failed: %v", err)
		_, err = netlink.LinkByAlias(*iface)
		if err != nil {
			log.Fatal("Linked failed: %v", err)
			_, err = netlink.LinkByIndex(0)
			if err != nil {
				log.Fatal("Linked failed: %v", err)
			}
		}
	}
	// Create eBPF system / load .ELF files compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err = bpf.LoadElf(*elf)
	if err != nil {
		log.Fatal("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	// Find special "PERF_EVENT" eBPF map
	perfmap := bpf.GetMapByName("perfmap")
	if perfmap == nil {
		log.Fatal("eBPF map 'perfmap' not found")
	}
	// Program name matches function name in xdp.c:
	//      int xdp_dump(struct xdp_md *ctx)
	xdp := bpf.GetProgramByName(*programName)
	if xdp == nil {
		log.Fatal("Program '%s' not found.", "xdp_dump")
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
	defer func() {
		if r := recover(); r != nil {
			log.Println("panic", r)
		}
		xdp.Detach()
	}()

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Start listening to Perf Events
	perf, _ := goebpf.NewPerfEvents(perfmap)
	perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		log.Fatal("perf.StartForAllProcessesAndCPUs(): %v", err)
	}

	log.Println("XDP program successfully loaded and attached.")
	log.Println("All new TCP connection requests (SYN) coming to this host will be dumped here.")
	log.Println()

	go func() {
		for {
			if data, ok := <-perfEvents; ok {
				//packet := gopacket.NewPacket()
				if len(data)-metadataSize > 0 {
					// event contains packet sample as well
					packet := gopacket.NewPacket(data[metadataSize:], layers.LayerTypeEthernet, gopacket.Default)
					fmt.Println(packet.String())
				}
				// fmt.Println(data)
			} else {
				break
			}
		}
	}()

	// Wait until Ctrl+C pressed
	<-ctrlC

	// Stop perf events and print summary
	perf.Stop()
	log.Println("\nSummary:")
	log.Printf("\t%d Event(s) Received\n", perf.EventsReceived)
	log.Printf("\t%d Event(s) lost (e.g. small buffer, delays in processing)\n", perf.EventsLost)
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
