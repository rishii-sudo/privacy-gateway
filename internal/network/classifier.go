package network

import (
	"net"
	"strings"
)

// InterfaceType categorizes the physical or logical nature of a network interface.
type InterfaceType string

const (
	TypePhysicalEthernet InterfaceType = "Physical Ethernet"
	TypePhysicalWiFi     InterfaceType = "Physical Wi-Fi"
	TypeVirtualVM        InterfaceType = "Virtual (VM)"
	TypeVirtualVPN       InterfaceType = "Virtual (VPN/Tunnel)"
	TypeLoopback         InterfaceType = "Loopback"
	TypeDown             InterfaceType = "Down"
	TypeUnknown          InterfaceType = "Unknown"

	// Legacy backward compatibility aliases
	TypePhysical = TypePhysicalEthernet
	TypeVirtual  = TypeVirtualVPN
)

// IsPhysical returns true if the adapter is a confirmed physical Ethernet or Wi-Fi interface.
func (t InterfaceType) IsPhysical() bool {
	return t == TypePhysicalEthernet || t == TypePhysicalWiFi
}

// IsVirtual returns true if the adapter is a VM or VPN/tunnel virtual interface.
func (t InterfaceType) IsVirtual() bool {
	return t == TypeVirtualVM || t == TypeVirtualVPN
}

// IsVM returns true if the adapter belongs to a virtual machine hypervisor (VMware, VirtualBox, Hyper-V, etc.).
func (t InterfaceType) IsVM() bool {
	return t == TypeVirtualVM
}

// IsVPN returns true if the adapter is an encrypted tunnel or VPN interface.
func (t InterfaceType) IsVPN() bool {
	return t == TypeVirtualVPN
}

// IsLoopback returns true if the adapter is software loopback.
func (t InterfaceType) IsLoopback() bool {
	return t == TypeLoopback
}

// IsDown returns true if the interface is administratively or operationally down.
func (t InterfaceType) IsDown() bool {
	return t == TypeDown
}

// IsUnknown returns true if interface metadata was insufficient to reliably classify the interface.
func (t InterfaceType) IsUnknown() bool {
	return t == TypeUnknown
}

// AdapterMetadata contains platform-specific metadata discovered for an adapter.
type AdapterMetadata struct {
	FriendlyName string
	Description  string
	IfType       uint32
	IsWireless   bool
	IsPhysical   bool
	IsVirtual    bool
	Driver       string
}

// Known VM vendor MAC address prefixes (OUIs).
var vmwareOUIs = []string{"00:50:56", "00:0c:29", "00:05:69", "00:1c:14"}
var virtualBoxOUIs = []string{"08:00:27"}
var hyperVOUIs = []string{"00:15:5d"}
var qemuOUIs = []string{"52:54:00"}
var parallelsOUIs = []string{"00:1c:42"}
var xenOUIs = []string{"00:16:3e"}

// MatchVMOUI checks if the MAC address matches known virtualization vendors.
func MatchVMOUI(mac string) bool {
	cleanMAC := strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
	if len(cleanMAC) < 8 {
		return false
	}
	prefix := cleanMAC[:8]

	for _, p := range vmwareOUIs {
		if prefix == p {
			return true
		}
	}
	for _, p := range virtualBoxOUIs {
		if prefix == p {
			return true
		}
	}
	for _, p := range hyperVOUIs {
		if prefix == p {
			return true
		}
	}
	for _, p := range qemuOUIs {
		if prefix == p {
			return true
		}
	}
	for _, p := range parallelsOUIs {
		if prefix == p {
			return true
		}
	}
	for _, p := range xenOUIs {
		if prefix == p {
			return true
		}
	}
	return false
}

// ClassifyByMetadata takes an interface and any platform-specific metadata to deterministically classify it.
// If reliable classification is impossible, it returns TypeUnknown instead of guessing.
func ClassifyByMetadata(iface net.Interface, meta *AdapterMetadata, customVPNPrefixes []string) InterfaceType {
	// 1. Check if interface is administratively DOWN
	if iface.Flags&net.FlagUp == 0 {
		return TypeDown
	}

	// 2. Check if interface is software LOOPBACK
	if iface.Flags&net.FlagLoopback != 0 {
		return TypeLoopback
	}

	nameLower := strings.ToLower(iface.Name)
	descLower := ""
	if meta != nil {
		descLower = strings.ToLower(meta.Description)
	}

	// 3. Virtual Machine (VM) Adapter Classification
	// Direct OUI match for VMware, VirtualBox, Hyper-V, QEMU
	if MatchVMOUI(iface.HardwareAddr.String()) {
		return TypeVirtualVM
	}

	// VMware: Specifically identify VMware VMnet1, VMnet8 and all VMware adapters
	if strings.Contains(nameLower, "vmware") || strings.Contains(nameLower, "vmnet") ||
		strings.Contains(descLower, "vmware") || strings.Contains(descLower, "vmnet") {
		return TypeVirtualVM
	}

	// VirtualBox
	if strings.Contains(nameLower, "virtualbox") || strings.Contains(nameLower, "vbox") ||
		strings.Contains(descLower, "virtualbox") || strings.Contains(descLower, "vboxnet") {
		return TypeVirtualVM
	}

	// Hyper-V & WSL
	if strings.Contains(nameLower, "hyper-v") || strings.Contains(nameLower, "vethernet") ||
		strings.Contains(descLower, "hyper-v") || strings.Contains(nameLower, "wsl") {
		return TypeVirtualVM
	}

	// QEMU / KVM / Bridge / Containers
	if strings.Contains(nameLower, "virbr") || strings.Contains(nameLower, "docker") ||
		strings.Contains(nameLower, "veth") || strings.Contains(descLower, "virtio") ||
		strings.Contains(nameLower, "cni0") || strings.Contains(nameLower, "flannel") {
		return TypeVirtualVM
	}

	// 4. VPN / Encrypted Tunnel Classification
	// Windows IfType 131 = IF_TYPE_TUNNEL, 23 = IF_TYPE_PPP, 53 = IF_TYPE_PROP_VIRTUAL
	if meta != nil && (meta.IfType == 131 || meta.IfType == 23 || meta.IfType == 53) {
		return TypeVirtualVPN
	}

	// Known VPN keywords in description or name
	vpnKeywords := []string{
		"wireguard", "openvpn", "tailscale", "proton", "nord", "mullvad",
		"expressvpn", "surfshark", "zerotier", "hamachi", "tap-windows",
		"wintun", "tunnel", "point-to-point",
	}
	for _, kw := range vpnKeywords {
		if strings.Contains(nameLower, kw) || strings.Contains(descLower, kw) {
			return TypeVirtualVPN
		}
	}

	// Custom user-configured VPN prefixes
	for _, p := range customVPNPrefixes {
		pLower := strings.ToLower(p)
		if strings.HasPrefix(nameLower, pLower) || strings.Contains(nameLower, pLower) ||
			strings.Contains(descLower, pLower) {
			return TypeVirtualVPN
		}
	}

	// Default VPN prefixes (tun, tap, wg, ppp)
	defaultVPNPrefixes := []string{"tun", "tap", "wg", "ppp", "utun"}
	for _, p := range defaultVPNPrefixes {
		if strings.HasPrefix(nameLower, p) {
			return TypeVirtualVPN
		}
	}

	// 5. Physical Wi-Fi Classification
	// Windows IfType 71 = IF_TYPE_IEEE80211 (Native Wi-Fi)
	if meta != nil && meta.IfType == 71 {
		return TypePhysicalWiFi
	}
	if meta != nil && meta.IsWireless {
		return TypePhysicalWiFi
	}
	if strings.Contains(nameLower, "wi-fi") || strings.Contains(nameLower, "wifi") ||
		strings.Contains(nameLower, "wlan") || strings.Contains(descLower, "wireless") ||
		strings.Contains(descLower, "802.11") || strings.Contains(descLower, "wi-fi") {
		return TypePhysicalWiFi
	}

	// 6. Physical Ethernet Classification
	// Windows IfType 6 = IF_TYPE_ETHERNET_CSMACD with physical hardware description
	if meta != nil && meta.IfType == 6 && meta.IsPhysical {
		return TypePhysicalEthernet
	}
	if strings.Contains(descLower, "pcie") || strings.Contains(descLower, "gigabit") ||
		strings.Contains(descLower, "gbe") || strings.Contains(descLower, "family controller") ||
		strings.Contains(descLower, "ethernet connection") || strings.Contains(descLower, "fast ethernet") {
		return TypePhysicalEthernet
	}

	// Linux standard physical device indicator
	if meta != nil && meta.IsPhysical {
		return TypePhysicalEthernet
	}

	// Standard Ethernet name patterns without virtual markers
	if (strings.HasPrefix(nameLower, "eth") || strings.HasPrefix(nameLower, "enp") ||
		strings.HasPrefix(nameLower, "ens") || strings.HasPrefix(nameLower, "eno") ||
		nameLower == "ethernet") && !strings.Contains(descLower, "virtual") && !strings.Contains(nameLower, "virtual") {
		return TypePhysicalEthernet
	}

	// 7. If classification cannot be determined reliably, return TypeUnknown
	// This enforces: "If reliable interface classification is unavailable, return INCONCLUSIVE instead of guessing."
	return TypeUnknown
}
