package main

import (
	"flag"
	"log"
	"os"
	"os/signal"

	//"github.com/dropbox/goebpf"
	"github.com/alex60217101990/goebpf"
)

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "./ddos_syn.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "xdp_ddos", "Name of XDP program (function name)")

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
