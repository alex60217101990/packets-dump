package configs

import (
	"github.com/alex60217101990/types/models/fw"
)

type Configs struct {
	Firewall *Firewall `yaml:"firewall"`
}

type Firewall struct {
	NetIfaceName   *string      `yaml:"net_iface_name" json:"omitempty,net_iface_name"`
	ElfFilePath    *string      `yaml:"elf_file_path" json:"omitempty,elf_file_path"`
	IPv4BlackList  []string     `yaml:"ipv4_blacklist" json:"omitempty,ipv4_blacklist"`
	IPv6BlackList  []string     `yaml:"ipv6_blacklist" json:"omitempty,ipv6_blacklist"`
	PortsBlacklist []fw.PortKey `yaml:"ports_blacklist" json:"omitempty,ports_blacklist"`
}
