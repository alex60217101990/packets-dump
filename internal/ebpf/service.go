package ebpf

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/alex60217101990/goebpf/cgotypes"
	"github.com/alex60217101990/packets-dump/internal/consts"
	"github.com/alex60217101990/types/configs"
	"github.com/alex60217101990/types/errors"

	//"github.com/dropbox/goebpf"
	"github.com/alex60217101990/goebpf"
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
		log.Fatalln(errors.ErrBpfSystemConfigNil)
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
			// log.Printf("ebpf init fatal: %v\n", r.(error))
			errors.ErrBpfInitFatal(r.(error))
		}
		l.Close()
	}()
	if l.configs.Firewall.ElfFilePath == nil {
		*l.configs.Firewall.ElfFilePath = consts.DefaultFwElfFilePath
	}
	err := l.bpf.LoadElf(*l.configs.Firewall.ElfFilePath)
	if err != nil {
		log.Println(errors.ErrLoadingFwElfFile(err))
		os.Exit(1)
	}
	// TODO: load other files...
	l.printBpfInfo()
	// Get eBPF maps:
	macBlacklist := l.bpf.GetMapByName(consts.MacBlacklist)
	if macBlacklist == nil {
		log.Println(errors.ErrMapNotFound(consts.MacBlacklist))
		os.Exit(1)
	}
	l.xdpMapsMap.Store(consts.MacBlacklist, macBlacklist)
	ipv4Blacklist := l.bpf.GetMapByName(consts.IPv4Blacklist)
	if ipv4Blacklist == nil {
		log.Println(errors.ErrMapNotFound(consts.IPv4Blacklist))
		os.Exit(1)
	}
	l.xdpMapsMap.Store(consts.IPv4Blacklist, ipv4Blacklist)
	ipv6Blacklist := l.bpf.GetMapByName(consts.IPv6Blacklist)
	if ipv6Blacklist == nil {
		log.Println(errors.ErrMapNotFound(consts.IPv6Blacklist))
		os.Exit(1)
	}
	l.xdpMapsMap.Store(consts.IPv6Blacklist, ipv6Blacklist)
	portBlacklist := l.bpf.GetMapByName(consts.PortBlacklist)
	if portBlacklist == nil {
		log.Println(errors.ErrMapNotFound(consts.PortBlacklist))
		os.Exit(1)
	}
	l.xdpMapsMap.Store(consts.PortBlacklist, ipv6Blacklist)
	// Program name matches function name in C file:
	fwXdpProg := l.bpf.GetProgramByName(consts.DefaultFwXdpProgName)
	if fwXdpProg == nil {
		log.Println(errors.ErrProgNotFound(consts.DefaultFwXdpProgName))
		os.Exit(1)
	}
	l.xdpProgMap.Store(consts.DefaultFwXdpProgName, fwXdpProg)
	if l.configs.Firewall.NetIfaceName == nil {
		*l.configs.Firewall.NetIfaceName = consts.DockerNetInterfaceName
	}
	// Load XDP program into kernel:
	err = fwXdpProg.Load()
	if err != nil {
		log.Println(errors.ErrLoadXdpProg(consts.DefaultFwXdpProgName, err))
		os.Exit(1)
	}
	log.Println("Load fw program success.")
	// Attach to interface:
	err = fwXdpProg.Attach(*l.configs.Firewall.NetIfaceName)
	if err != nil {
		log.Println(errors.ErrAttachXdpProg(consts.DefaultFwXdpProgName, *l.configs.Firewall.NetIfaceName, err))
		os.Exit(1)
	}
	log.Printf("Attach: %s namespace success.\n", *l.configs.Firewall.NetIfaceName)
	err = l.FwLoadBlacklists()
	if err != nil {
		log.Println(errors.ErrLoadFwBlacklists(err))
		os.Exit(1)
	}
}

func (l *BpfLoader) FwLoadBlacklists() (err error) {
	err = l.loadMacBlacklist()
	if err != nil {
		return err
	}
	err = l.loadPortBlacklist()
	if err != nil {
		return err
	}
	err = l.loadIPv4Blacklist()
	if err != nil {
		return err
	}
	err = l.loadIPv6Blacklist()
	return err
}

func (l *BpfLoader) loadMacBlacklist() error {
	var (
		mac cgotypes.MacKey
		err error
	)
	for _, macStr := range l.configs.Firewall.MacBlacklist {
		mac, err = cgotypes.ParseFromSrtMac(macStr)
		if err != nil {
			log.Println(errors.ErrParseMACAddr(mac, err))
			continue
		}
		err = l.Upsert(mac)
		// if err != nil {
		// 	log.Printf("load MAC addr: %s, to xdp map: %s, error: %v\n", mac, consts.MacBlacklist, err)
		// }
	}
	return err
}

func (l *BpfLoader) loadIPv4Blacklist() (err error) {
	var ipKey cgotypes.LpmV4Key
	for _, ipStr := range l.configs.Firewall.IPv4BlackList {
		ipKey, err = cgotypes.ParseFromSrtV4(ipStr)
		if err == nil {
			err = l.Upsert(ipKey)
		}
	}
	return err
}

func (l *BpfLoader) loadIPv6Blacklist() (err error) {
	var ipKey cgotypes.LpmV6Key
	for _, ipStr := range l.configs.Firewall.IPv6BlackList {
		ipKey, err = cgotypes.ParseFromSrtV6(ipStr)
		if err == nil {
			err = l.Upsert(ipKey)
		}
	}
	return err
}

func (l *BpfLoader) loadPortBlacklist() (err error) {
	for _, portKey := range l.configs.Firewall.PortsBlacklist {
		if portKey != nil {
			err = l.Upsert(*portKey)
		}
	}
	return err
}

func (l *BpfLoader) Upsert(event interface{}) error {
	switch e := event.(type) {
	case cgotypes.PortKey:
		fmt.Println(111)
		if m, ok := l.xdpMapsMap.Load(consts.PortBlacklist); ok {
			err := m.(goebpf.Map).Upsert(e, true)
			fmt.Println(222)
			return err
		}
	case cgotypes.LpmV4Key:
		if m, ok := l.xdpMapsMap.Load(consts.IPv4Blacklist); ok {
			return m.(goebpf.Map).Upsert(e, true)
		}
	case cgotypes.LpmV6Key:
		if m, ok := l.xdpMapsMap.Load(consts.IPv6Blacklist); ok {
			return m.(goebpf.Map).Upsert(e, true)
		}
	case cgotypes.MacKey:
		if m, ok := l.xdpMapsMap.Load(consts.MacBlacklist); ok {
			return m.(goebpf.Map).Upsert(e, true)
		}
	}
	return errors.ErrXdpMapKeyDataType
}

func (l *BpfLoader) Delete(event interface{}) error {
	switch e := event.(type) {
	case cgotypes.PortKey:
		if m, ok := l.xdpMapsMap.Load(consts.PortBlacklist); ok {
			return m.(goebpf.Map).Delete(e)
		}
	case cgotypes.LpmV4Key:
		if m, ok := l.xdpMapsMap.Load(consts.IPv4Blacklist); ok {
			return m.(goebpf.Map).Delete(e)
		}
	case cgotypes.LpmV6Key:
		if m, ok := l.xdpMapsMap.Load(consts.IPv6Blacklist); ok {
			return m.(goebpf.Map).Delete(e)
		}
	case cgotypes.MacKey:
		if m, ok := l.xdpMapsMap.Load(consts.MacBlacklist); ok {
			return m.(goebpf.Map).Delete(e)
		}
	}
	return errors.ErrXdpMapKeyDataType
}

func (l *BpfLoader) AttachIfaceToFwXdp(iface string) error {
	if xdpProg, ok := l.xdpProgMap.Load(consts.DefaultFwXdpProgName); ok {
		return xdpProg.(goebpf.Program).Attach(iface)
	}
	return errors.ErrAttachIfaceToXdpProg(iface)
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
