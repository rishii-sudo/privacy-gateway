package network

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestEnumerateInterfaces(t *testing.T) {
	enum := NewEnumerator(nil, 2*time.Second)
	ifaces, err := enum.EnumerateInterfaces()
	if err != nil {
		t.Fatalf("failed to enumerate interfaces: %v", err)
	}

	if len(ifaces) == 0 {
		t.Fatalf("expected at least one network interface, got 0")
	}

	for _, iface := range ifaces {
		if iface.MACAddress != "" && iface.RedactedMAC == "" {
			t.Errorf("MAC was present but redacted MAC is empty")
		}
	}
}

func TestClassifyVMwareAdapters(t *testing.T) {
	// VMware VMnet1 and VMnet8 must be classified as TypeVirtualVM, NOT physical
	vmnet1 := net.Interface{
		Index:        14,
		Name:         "VMware Network Adapter VMnet1",
		HardwareAddr: net.HardwareAddr{0x00, 0x50, 0x56, 0xc0, 0x00, 0x01},
		Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
	}
	metaVMnet1 := &AdapterMetadata{
		FriendlyName: "VMware Network Adapter VMnet1",
		Description:  "VMware Virtual Ethernet Adapter for VMnet1",
		IfType:       6,
		IsVirtual:    true,
		IsPhysical:   false,
	}

	res1 := ClassifyByMetadata(vmnet1, metaVMnet1, nil)
	if res1 != TypeVirtualVM {
		t.Errorf("expected VMware VMnet1 to be TypeVirtualVM, got %s", res1)
	}
	if res1.IsPhysical() {
		t.Errorf("VMware VMnet1 must NOT be classified as physical")
	}
	if !res1.IsVM() {
		t.Errorf("VMware VMnet1 must be classified as VM")
	}

	vmnet8 := net.Interface{
		Index:        15,
		Name:         "VMware Network Adapter VMnet8",
		HardwareAddr: net.HardwareAddr{0x00, 0x50, 0x56, 0xc0, 0x00, 0x08},
		Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
	}
	metaVMnet8 := &AdapterMetadata{
		FriendlyName: "VMware Network Adapter VMnet8",
		Description:  "VMware Virtual Ethernet Adapter for VMnet8",
		IfType:       6,
		IsVirtual:    true,
		IsPhysical:   false,
	}

	res8 := ClassifyByMetadata(vmnet8, metaVMnet8, nil)
	if res8 != TypeVirtualVM {
		t.Errorf("expected VMware VMnet8 to be TypeVirtualVM, got %s", res8)
	}
	if res8.IsPhysical() {
		t.Errorf("VMware VMnet8 must NOT be classified as physical")
	}
}

func TestClassifyPhysicalWiFi(t *testing.T) {
	wifiIface := net.Interface{
		Index:        24,
		Name:         "Wi-Fi",
		HardwareAddr: net.HardwareAddr{0x08, 0xf9, 0xe0, 0x11, 0x22, 0x33},
		Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
	}
	metaWiFi := &AdapterMetadata{
		FriendlyName: "Wi-Fi",
		Description:  "MediaTek Wi-Fi 7 MT7925 Wireless LAN Card",
		IfType:       71, // IF_TYPE_IEEE80211
		IsWireless:   true,
		IsPhysical:   true,
	}

	res := ClassifyByMetadata(wifiIface, metaWiFi, nil)
	if res != TypePhysicalWiFi {
		t.Errorf("expected TypePhysicalWiFi, got %s", res)
	}
	if !res.IsPhysical() {
		t.Errorf("expected IsPhysical() == true for Wi-Fi")
	}
	if res.IsVM() || res.IsVPN() {
		t.Errorf("Wi-Fi must not be marked as VM or VPN")
	}
}

func TestClassifyPhysicalEthernet(t *testing.T) {
	ethIface := net.Interface{
		Index:        4,
		Name:         "Ethernet",
		HardwareAddr: net.HardwareAddr{0x4c, 0xc5, 0xaa, 0xbb, 0xcc, 0xdd},
		Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
	}
	metaEth := &AdapterMetadata{
		FriendlyName: "Ethernet",
		Description:  "Realtek PCIe GbE Family Controller",
		IfType:       6, // IF_TYPE_ETHERNET_CSMACD
		IsWireless:   false,
		IsPhysical:   true,
	}

	res := ClassifyByMetadata(ethIface, metaEth, nil)
	if res != TypePhysicalEthernet {
		t.Errorf("expected TypePhysicalEthernet, got %s", res)
	}
	if !res.IsPhysical() {
		t.Errorf("expected IsPhysical() == true for Ethernet")
	}
}

func TestClassifyVPNAdapters(t *testing.T) {
	// 1. Windows TAP adapter
	tapIface := net.Interface{
		Index:        11,
		Name:         "Local Area Connection",
		HardwareAddr: net.HardwareAddr{0x00, 0xff, 0x11, 0x22, 0x33, 0x44},
		Flags:        net.FlagUp,
	}
	metaTAP := &AdapterMetadata{
		FriendlyName: "Local Area Connection",
		Description:  "TAP-ProtonVPN Windows Adapter V9",
		IfType:       53, // IF_TYPE_PROP_VIRTUAL
		IsVirtual:    true,
	}
	resTAP := ClassifyByMetadata(tapIface, metaTAP, nil)
	if resTAP != TypeVirtualVPN {
		t.Errorf("expected TAP adapter to be TypeVirtualVPN, got %s", resTAP)
	}
	if !resTAP.IsVPN() {
		t.Errorf("expected IsVPN() == true")
	}

	// 2. WireGuard interface
	wgIface := net.Interface{
		Name:  "wg0",
		Flags: net.FlagUp,
	}
	metaWG := &AdapterMetadata{
		FriendlyName: "wg0",
		Description:  "WireGuard Tunnel",
		IfType:       131, // IF_TYPE_TUNNEL
		IsVirtual:    true,
	}
	resWG := ClassifyByMetadata(wgIface, metaWG, nil)
	if resWG != TypeVirtualVPN {
		t.Errorf("expected WireGuard adapter to be TypeVirtualVPN, got %s", resWG)
	}

	// 3. Tailscale interface
	tsIface := net.Interface{
		Name:  "tailscale0",
		Flags: net.FlagUp,
	}
	resTS := ClassifyByMetadata(tsIface, nil, []string{"tailscale"})
	if resTS != TypeVirtualVPN {
		t.Errorf("expected tailscale0 to be TypeVirtualVPN, got %s", resTS)
	}
}

func TestClassifyLoopbackAndDown(t *testing.T) {
	loIface := net.Interface{
		Name:  "lo",
		Flags: net.FlagUp | net.FlagLoopback,
	}
	if res := ClassifyByMetadata(loIface, nil, nil); res != TypeLoopback {
		t.Errorf("expected TypeLoopback, got %s", res)
	}

	downIface := net.Interface{
		Name:  "eth1",
		Flags: 0,
	}
	if res := ClassifyByMetadata(downIface, nil, nil); res != TypeDown {
		t.Errorf("expected TypeDown, got %s", res)
	}
}

func TestClassifyUnknownAdapter(t *testing.T) {
	// An adapter with no metadata and an ambiguous, unrecognized name must return TypeUnknown
	unknownIface := net.Interface{
		Name:         "misc_interface_xyz",
		HardwareAddr: net.HardwareAddr{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
		Flags:        net.FlagUp,
	}
	res := ClassifyByMetadata(unknownIface, nil, nil)
	if res != TypeUnknown {
		t.Errorf("expected TypeUnknown for unclassifiable adapter, got %s", res)
	}
	if !res.IsUnknown() {
		t.Errorf("expected IsUnknown() == true")
	}
}

func TestMixedInterfaceEnvironment(t *testing.T) {
	// Replicates realistic host state with mixed adapters:
	// - Ethernet (Realtek, DOWN)
	// - Wi-Fi (MediaTek, UP)
	// - VMware VMnet1 (Virtual VM, UP)
	// - VMware VMnet8 (Virtual VM, UP)
	// - TAP-ProtonVPN (Virtual VPN, DOWN)
	// - Loopback (Loopback, UP)
	interfaces := []struct {
		iface    net.Interface
		meta     *AdapterMetadata
		expected InterfaceType
	}{
		{
			iface: net.Interface{
				Index: 4, Name: "Ethernet", Flags: 0, // DOWN
			},
			meta:     &AdapterMetadata{Description: "Realtek PCIe GbE Family Controller", IfType: 6},
			expected: TypeDown,
		},
		{
			iface: net.Interface{
				Index: 24, Name: "Wi-Fi", Flags: net.FlagUp | net.FlagBroadcast,
			},
			meta:     &AdapterMetadata{Description: "MediaTek Wi-Fi 7 MT7925 Wireless LAN Card", IfType: 71, IsWireless: true, IsPhysical: true},
			expected: TypePhysicalWiFi,
		},
		{
			iface: net.Interface{
				Index: 14, Name: "VMware Network Adapter VMnet1", HardwareAddr: net.HardwareAddr{0x00, 0x50, 0x56, 0xc0, 0x00, 0x01}, Flags: net.FlagUp,
			},
			meta:     &AdapterMetadata{Description: "VMware Virtual Ethernet Adapter for VMnet1", IfType: 6, IsVirtual: true},
			expected: TypeVirtualVM,
		},
		{
			iface: net.Interface{
				Index: 15, Name: "VMware Network Adapter VMnet8", HardwareAddr: net.HardwareAddr{0x00, 0x50, 0x56, 0xc0, 0x00, 0x08}, Flags: net.FlagUp,
			},
			meta:     &AdapterMetadata{Description: "VMware Virtual Ethernet Adapter for VMnet8", IfType: 6, IsVirtual: true},
			expected: TypeVirtualVM,
		},
		{
			iface: net.Interface{
				Index: 1, Name: "Loopback Pseudo-Interface 1", Flags: net.FlagUp | net.FlagLoopback,
			},
			meta:     &AdapterMetadata{Description: "Software Loopback Interface 1", IfType: 24},
			expected: TypeLoopback,
		},
	}

	physicalUpCount := 0
	vmCount := 0

	for _, item := range interfaces {
		res := ClassifyByMetadata(item.iface, item.meta, nil)
		if res != item.expected {
			t.Errorf("for interface %s: expected %s, got %s", item.iface.Name, item.expected, res)
		}
		if res.IsPhysical() && item.iface.Flags&net.FlagUp != 0 {
			physicalUpCount++
		}
		if res.IsVM() {
			vmCount++
		}
	}

	// In this mixed environment, ONLY Wi-Fi is active physical; VMware VMnet1 and VMnet8 are VM adapters
	if physicalUpCount != 1 {
		t.Errorf("expected exactly 1 active physical adapter (Wi-Fi), got %d", physicalUpCount)
	}
	if vmCount != 2 {
		t.Errorf("expected exactly 2 VM adapters (VMnet1 and VMnet8), got %d", vmCount)
	}
}

func TestRedactHardwareAddr(t *testing.T) {
	mac := "00:11:22:33:44:55"
	redacted := redactHardwareAddr(mac)
	if strings.Contains(redacted, "22:33:44") {
		t.Fatalf("MAC middle octets not redacted: %s", redacted)
	}
	if !strings.HasPrefix(redacted, "00:11:") || !strings.HasSuffix(redacted, ":55") {
		t.Fatalf("unexpected redacted format: %s", redacted)
	}

	if redactHardwareAddr("") != "none" {
		t.Fatalf("expected none for empty MAC")
	}
}

func TestParseFlags(t *testing.T) {
	flags := parseFlags(net.FlagUp | net.FlagBroadcast | net.FlagMulticast)
	hasUp := false
	hasBcast := false
	for _, f := range flags {
		if f == "UP" {
			hasUp = true
		}
		if f == "BROADCAST" {
			hasBcast = true
		}
	}
	if !hasUp || !hasBcast {
		t.Errorf("flags parse missed expected flags: %v", flags)
	}
}
