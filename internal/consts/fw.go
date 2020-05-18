package consts

const (
	DefaultFwElfFilePath string = "./fw.elf"
	DefaultFwXdpProgName string = "xdp_drop" //"xdp_fw"
	// Map names
	MacBlacklist     string = "mac_blacklist"
	IPv4Blacklist    string = "v4_blacklist"
	IPv6Blacklist    string = "v6_blacklist"
	PortUDPBlacklist string = "ports_udp"
	PortTCPBlacklist string = "ports_tcp"

	// Perf map names
	PortPerfMap string = "perfmap_port"
)
