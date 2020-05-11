package ebpf

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/alex60217101990/packets-dump/internal/configs"
	"github.com/alex60217101990/packets-dump/internal/consts"
	"github.com/dropbox/goebpf"
)

type BpfLoader struct {
	configs    *configs.Configs
	bpf        goebpf.System
	xdpMapsMap sync.Map // map[string]goebpf.Map
	xdpProgMap sync.Map // map[string]goebpf.Program
}

func NewBpfLoader(options ...func(*BpfLoader) error) *BpfLoader {
	l := &BpfLoader{
		bpf: goebpf.NewDefaultEbpfSystem(),
		// xdpMapsMap: make(map[string]goebpf.Map),
		// xdpProgMap: make(map[string]goebpf.Program),
	}
	for _, op := range options {
		err := op(l)
		if err != nil {
			log.Fatalln(err)
		}
	}
	if l.configs == nil {
		log.Fatalln("system configs not set")
	}
	return l
}

func SetConfigs(conf *configs.Configs) func(*BpfLoader) error {
	return func(service *BpfLoader) error {
		service.configs = conf
		return nil
	}
}

func (l *BpfLoader) Init() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ebpf init fatal: %v\n", r.(error))
		}
		l.Close()
	}()
	if l.configs.Firewall.ElfFilePath == nil {
		*l.configs.Firewall.ElfFilePath = consts.DefaultFwElfFilePath
	}
	err := l.bpf.LoadElf(*l.configs.Firewall.ElfFilePath)
	if err != nil {
		log.Fatalf("Loading firewall elf file failed: %v\n", err)
	}
	// TODO: load other files...
	l.printBpfInfo()
	// Get eBPF maps:
	macBlacklist := l.bpf.GetMapByName(consts.MacBlacklist)
	if macBlacklist == nil {
		log.Fatalf("eBPF map '%s' not found\n", consts.MacBlacklist)
	}
	l.xdpMapsMap.Store(consts.MacBlacklist, macBlacklist)
	ipv4Blacklist := l.bpf.GetMapByName(consts.IPv4Blacklist)
	if ipv4Blacklist == nil {
		log.Fatalf("eBPF map '%s' not found\n", consts.IPv4Blacklist)
	}
	l.xdpMapsMap.Store(consts.IPv4Blacklist, ipv4Blacklist)
	ipv6Blacklist := l.bpf.GetMapByName(consts.IPv6Blacklist)
	if ipv6Blacklist == nil {
		log.Fatalf("eBPF map '%s' not found\n", consts.IPv6Blacklist)
	}
	l.xdpMapsMap.Store(consts.IPv6Blacklist, ipv6Blacklist)
	portBlacklist := l.bpf.GetMapByName(consts.PortBlacklist)
	if portBlacklist == nil {
		log.Fatalf("eBPF map '%s' not found\n", consts.PortBlacklist)
	}
	l.xdpMapsMap.Store(consts.PortBlacklist, ipv6Blacklist)
	// Program name matches function name in C file:
	fwXdpProg := l.bpf.GetProgramByName(consts.DefaultFwXdpProgName)
	if fwXdpProg == nil {
		log.Fatalf("Program '%s' not found.\n", consts.DefaultFwXdpProgName)
	}
	l.xdpProgMap.Store(consts.DefaultFwXdpProgName, fwXdpProg)
	if l.configs.Firewall.NetIfaceName == nil {
		*l.configs.Firewall.NetIfaceName = consts.DockerNetInterfaceName
	}
	// Load XDP program into kernel:
	err = fwXdpProg.Load()
	if err != nil {
		log.Fatalf("Loading %s xdp program failed: %v\n", consts.DefaultFwXdpProgName, err)
	}
	// Attach to interface:
	err = fwXdpProg.Attach(*l.configs.Firewall.NetIfaceName)
	if err != nil {
		log.Fatalf("Attach %s xdp program to iface: %s failed: %v\n", consts.DefaultFwXdpProgName, *l.configs.Firewall.NetIfaceName, err)
	}
}

func (l *BpfLoader) Upsert(event interface{}) error {
	switch e := event.(type) {
	case models.PortKey:
		if m, ok := l.xdpMapsMap.Load(consts.PortBlacklist); ok {
			return m.(goebpf.Map).Upsert(e, true)
		}
	case models.LpmV4Key:
		if m, ok := l.xdpMapsMap.Load(consts.IPv4Blacklist); ok {
			return m.(goebpf.Map).Upsert(e, true)
		}
	case models.LpmV6Key:
		if m, ok := l.xdpMapsMap.Load(consts.IPv6Blacklist); ok {
			return m.(goebpf.Map).Upsert(e, true)
		}
	case net.HardwareAddr:
		if m, ok := l.xdpMapsMap.Load(consts.MacBlacklist); ok {
			return m.(goebpf.Map).Upsert(e, true)
		}
	}
	return fmt.Errorf("invalid xdp map event data type")
}



func (l *BpfLoader) AttachIfaceToFwXdp(iface string) error {
	if xdpProg, ok := l.xdpProgMap.Load(consts.DefaultFwXdpProgName); ok {
		return xdpProg.(goebpf.Program).Attach(iface)
	}
	return fmt.Errorf("can't load %s program", consts.DefaultFwXdpProgName)
}

func (l *BpfLoader) Close() (err error) {
	l.xdpMapsMap.Range(func(k, v interface{}) bool {
		err = v.(goebpf.Map).Close()
		return true
	})
	l.xdpProgMap.Range(func(k, v interface{}) bool {
		err = v.(goebpf.Program).Detach()
		err = v.(goebpf.Program).Close()
		return true
	})
	return err
}

func (l *BpfLoader) printBpfInfo() {
	log.Println("Maps:")
	for _, item := range l.bpf.GetMaps() {
		m := item.(*goebpf.EbpfMap)
		log.Printf("\t%s: %v, Fd %v\n", m.Name, m.Type, m.GetFd())
	}
	log.Println("\nPrograms:")
	for _, prog := range l.bpf.GetPrograms() {
		log.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	log.Println()
}
