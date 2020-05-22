package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/dropbox/goebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
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

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &payload)
	decodedLayers := make([]gopacket.LayerType, 0, 10)

	go func() {
		for {
			if data, ok := <-perfEvents; ok {
				//packet := gopacket.NewPacket()
				if len(data)-metadataSize > 0 {
					// event contains packet sample as well
					// packet := gopacket.NewPacket(data[metadataSize:], layers.LayerTypeEthernet, gopacket.Default)
					// fmt.Println(packet.String())
					fmt.Println("Decoding packet")
					err = parser.DecodeLayers(data[metadataSize:], &decodedLayers)
					for _, typ := range decodedLayers {
						fmt.Println("  Successfully decoded layer type", typ)
						switch typ {
						case layers.LayerTypeEthernet:
							fmt.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
						case layers.LayerTypeIPv4:
							fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
						case layers.LayerTypeIPv6:
							fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
						case layers.LayerTypeTCP:
							fmt.Println("    TCP ", tcp.SrcPort, tcp.DstPort)
						case layers.LayerTypeUDP:
							fmt.Println("    UDP ", udp.SrcPort, udp.DstPort)
						}
					}
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
