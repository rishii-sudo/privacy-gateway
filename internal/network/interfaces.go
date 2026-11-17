package network

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// IPAddress represents an assigned network address with family classification.
type IPAddress struct {
	Address         string `json:"address"`
	CIDR            string `json:"cidr"`
	Family          string `json:"family"` // "IPv4" or "IPv6"
	IsLoop          bool   `json:"is_loopback"`
	IsGlobalUnicast bool   `json:"is_global_unicast"`
	IsPrivate       bool   `json:"is_private"`
}

// NetworkInterface encapsulates detailed state for a host network adapter.
type NetworkInterface struct {
	Index       int           `json:"index"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	MACAddress  string        `json:"mac_address"`
	RedactedMAC string        `json:"redacted_mac"`
	MTU         int           `json:"mtu"`
	Flags       []string      `json:"flags"`
	Type        InterfaceType `json:"type"`
	IsUp        bool          `json:"is_up"`
	Addresses   []IPAddress   `json:"addresses"`
	HasIPv4     bool          `json:"has_ipv4"`
	HasIPv6     bool          `json:"has_ipv6"`
}

// OutboundRouteCandidate contains the locally selected route candidate for Internet egress.
type OutboundRouteCandidate struct {
	LocalIP       string    `json:"local_ip"`
	InterfaceName string    `json:"interface_name"`
	ProbeTarget   string    `json:"probe_target"`
	Timestamp     time.Time `json:"timestamp"`
}

// NetworkEnumerator provides read-only discovery of host networking configuration.
type NetworkEnumerator struct {
	virtualPrefixes []string
	probeTimeout    time.Duration
}

// NewEnumerator initializes a NetworkEnumerator with custom virtual interface prefixes.
func NewEnumerator(virtualPrefixes []string, timeout time.Duration) *NetworkEnumerator {
	if len(virtualPrefixes) == 0 {
		virtualPrefixes = []string{"tun", "tap", "wg", "tailscale", "proton", "openvpn", "ppp", "utun"}
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &NetworkEnumerator{
		virtualPrefixes: virtualPrefixes,
		probeTimeout:    timeout,
	}
}

// EnumerateInterfaces performs read-only discovery of all local network interfaces.
func (e *NetworkEnumerator) EnumerateInterfaces() ([]NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to discover system network interfaces: %w", err)
	}

	var results []NetworkInterface

	for _, iface := range ifaces {
		meta := GetPlatformMetadata(iface)
		desc := ""
		if meta != nil {
			desc = meta.Description
		}

		ni := NetworkInterface{
			Index:       iface.Index,
			Name:        iface.Name,
			Description: desc,
			MACAddress:  iface.HardwareAddr.String(),
			RedactedMAC: redactHardwareAddr(iface.HardwareAddr.String()),
			MTU:         iface.MTU,
			Flags:       parseFlags(iface.Flags),
			IsUp:        iface.Flags&net.FlagUp != 0,
		}

		// Classify Interface Type using platform metadata, OUI, and known adapter patterns
		ni.Type = ClassifyByMetadata(iface, meta, e.virtualPrefixes)

		// Discover IP addresses
		addrs, err := iface.Addrs()
		if err == nil {
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok || ipNet.IP == nil {
					continue
				}

				ip := ipNet.IP
				family := "IPv4"
				if ip.To4() == nil {
					family = "IPv6"
					ni.HasIPv6 = true
				} else {
					ni.HasIPv4 = true
				}

				ipAddr := IPAddress{
					Address:         ip.String(),
					CIDR:            ipNet.String(),
					Family:          family,
					IsLoop:          ip.IsLoopback(),
					IsGlobalUnicast: ip.IsGlobalUnicast(),
					IsPrivate:       ip.IsPrivate(),
				}
				ni.Addresses = append(ni.Addresses, ipAddr)
			}
		}

		results = append(results, ni)
	}

	return results, nil
}

// DiscoverOutboundCandidate determines which local IP and interface the kernel routing table
// selects for outbound traffic.
// This uses a connectionless UDP socket connect without sending any packet over the wire.
// It is strictly read-only and emits zero network packets.
func (e *NetworkEnumerator) DiscoverOutboundCandidate(target string) (*OutboundRouteCandidate, error) {
	if target == "" {
		target = "1.1.1.1:53"
	}

	conn, err := net.DialTimeout("udp", target, e.probeTimeout)
	if err != nil {
		return nil, fmt.Errorf("route discovery connectionless probe failed: %w", err)
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected local address format")
	}

	candidateIP := localAddr.IP.String()

	// Correlate with discovered interfaces to find the interface name
	ifaces, err := e.EnumerateInterfaces()
	ifName := "unknown"
	if err == nil {
		for _, iface := range ifaces {
			for _, a := range iface.Addresses {
				if a.Address == candidateIP {
					ifName = iface.Name
					break
				}
			}
		}
	}

	return &OutboundRouteCandidate{
		LocalIP:       candidateIP,
		InterfaceName: ifName,
		ProbeTarget:   target,
		Timestamp:     time.Now().UTC(),
	}, nil
}

// classifyInterface categorizes an interface into Physical Ethernet, Physical Wi-Fi, Virtual VM, Virtual VPN, Loopback, Down, or Unknown.
func (e *NetworkEnumerator) classifyInterface(iface net.Interface) InterfaceType {
	meta := GetPlatformMetadata(iface)
	return ClassifyByMetadata(iface, meta, e.virtualPrefixes)
}

// parseFlags converts net.Flags bitmask into human-readable strings.
func parseFlags(f net.Flags) []string {
	var flags []string
	if f&net.FlagUp != 0 {
		flags = append(flags, "UP")
	}
	if f&net.FlagBroadcast != 0 {
		flags = append(flags, "BROADCAST")
	}
	if f&net.FlagLoopback != 0 {
		flags = append(flags, "LOOPBACK")
	}
	if f&net.FlagPointToPoint != 0 {
		flags = append(flags, "POINT_TO_POINT")
	}
	if f&net.FlagMulticast != 0 {
		flags = append(flags, "MULTICAST")
	}
	return flags
}

// redactHardwareAddr masks the middle octets of a MAC address for privacy preservation.
func redactHardwareAddr(mac string) string {
	if mac == "" {
		return "none"
	}
	parts := strings.FieldsFunc(mac, func(c rune) bool {
		return c == ':' || c == '-'
	})
	if len(parts) == 6 {
		return fmt.Sprintf("%s:%s:**:**:**:%s", parts[0], parts[1], parts[5])
	}
	return "**:**:**:**:**:**"
}
