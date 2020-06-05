package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"

	//"github.com/dropbox/goebpf"
	"github.com/alex60217101990/goebpf"
	"github.com/alex60217101990/types/helpers"
)

const (
	SO_BINDTODEVICE = 25
)

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "./proxy.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "proxy", "Name of XDP program (function name)")

// const (
// 	// Size of structure used to pass metadata
// 	metadataSize = 4
// )

// func main() {
// 	flag.Parse()
// 	if *iface == "" {
// 		log.Fatal("-iface is required.")
// 	}

// 	log.Println(helpers.IP2int(net.ParseIP("172.28.1.2")))

// 	// Add CTRL+C handler
// 	ctrlC := make(chan os.Signal, 1)
// 	signal.Notify(ctrlC, os.Interrupt)

// 	// Create eBPF system / load .ELF files compiled by clang/llvm
// 	bpf := goebpf.NewDefaultEbpfSystem()
// 	err := bpf.LoadElf(*elf)
// 	if err != nil {
// 		log.Fatal("LoadElf() failed: %v", err)
// 	}
// 	printBpfInfo(bpf)

// 	// Program name matches function name in socket_filter.c:
// 	//      int packet_counter(struct __sk_buff *skb)
// 	sf := bpf.GetProgramByName(*programName)
// 	if sf == nil {
// 		log.Fatal("Program '%s' not found. ", *programName)
// 	}

// 	// Load XDP program into kernel
// 	err = sf.Load()
// 	if err != nil {
// 		log.Fatal("sf.Load(): %v", err)
// 	}

// 	// Create RAW socket
// 	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL<<8) // htons(unix.ETH_P_ALL)
// 	if err != nil {
// 		log.Printf("unable to create raw socket: %v\n", err)
// 	}
// 	defer unix.Close(sock)

// 	// Bind raw socket to interface
// 	err = unix.SetsockoptString(sock, unix.SOL_SOCKET, SO_BINDTODEVICE, *iface)
// 	if err != nil {
// 		log.Printf("SO_BINDTODEVICE to %s failed: %v\n", *iface, err)
// 	}

// 	// Attach eBPF program to socket as socketFilter
// 	err = sf.Attach(goebpf.SocketFilterAttachParams{
// 		SocketFd:   sock,
// 		AttachType: goebpf.SocketAttachTypeFilter,
// 	})

// 	if err != nil {
// 		log.Printf("sf.Attach(): %v\n", err)
// 	}

// 	defer func() {
// 		if r := recover(); r != nil {
// 			log.Println("panic", r)
// 		}
// 		sf.Detach()
// 	}()

// 	log.Println("XDP program successfully loaded and attached.")
// 	log.Println("All new TCP connection requests (SYN) coming to this host will be dumped here.")
// 	log.Println()

// 	// Wait until Ctrl+C pressed
// 	<-ctrlC

// 	// Stop perf events and print summary
// 	log.Println("\nDetaching program and exit...")
// }

// func printBpfInfo(bpf goebpf.System) {
// 	log.Println("Maps:")
// 	for _, item := range bpf.GetMaps() {
// 		m := item.(*goebpf.EbpfMap)
// 		log.Printf("\t%s: %v, Fd %v\n", m.Name, m.Type, m.GetFd())
// 	}
// 	log.Println("\nPrograms:")
// 	for _, prog := range bpf.GetPrograms() {
// 		log.Printf("\t%s: %v, size %d, license \"%s\"\n",
// 			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
// 		)

// 	}
// 	log.Println()
// }

func main() {
	flag.Parse()
	if *iface == "" {
		log.Fatal("-iface is required.")
	}

	log.Println(helpers.IP2int(net.ParseIP("172.28.1.1")))

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
		log.Fatalf("Program '%s' not found. \n", *programName)
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
