package consts

const (
	DefaultFwElfFilePath string = "./fw.elf"
	DefaultFwXdpProgName string = "xdp_fw"
	// Map names
	MacBlacklist     string = "mac_blacklist"
	IPv4Blacklist    string = "v4_blacklist"
	IPv6Blacklist    string = "v6_blacklist"
	PortUDPBlacklist string = "port_udp_blacklist"
	PortTCPBlacklist string = "port_tcp_blacklist"

	// Perf map names
	PortPerfMap string = "perfmap_port"
)
