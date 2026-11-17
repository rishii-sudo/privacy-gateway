//go:build windows

package network

import (
	"net"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	modiphlpapi              = syscall.NewLazyDLL("iphlpapi.dll")
	procGetAdaptersAddresses = modiphlpapi.NewProc("GetAdaptersAddresses")

	cachedWindowsMeta map[int]*AdapterMetadata
	metaMu            sync.RWMutex
)

type rawAdapterAddresses struct {
	Length                uint32
	IfIndex               uint32
	Next                  *rawAdapterAddresses
	AdapterName           *byte
	FirstUnicastAddress   uintptr
	FirstAnycastAddress   uintptr
	FirstMulticastAddress uintptr
	FirstDnsServerAddress uintptr
	DnsSuffix             *uint16
	Description           *uint16
	FriendlyName          *uint16
	PhysicalAddress       [8]byte
	PhysicalAddressLength uint32
	Flags                 uint32
	Mtu                   uint32
	IfType                uint32
	OperStatus            uint32
	Ipv6IfIndex           uint32
	ZoneIndices           [16]uint32
	FirstPrefix           uintptr
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var u []uint16
	for ptr := p; *ptr != 0; ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2)) {
		u = append(u, *ptr)
	}
	return string(utf16.Decode(u))
}

// queryWindowsAdapters queries iphlpapi.dll GetAdaptersAddresses to retrieve kernel adapter metadata.
func queryWindowsAdapters() map[int]*AdapterMetadata {
	metaMap := make(map[int]*AdapterMetadata)

	size := uint32(15000)
	buf := make([]byte, size)
	flags := uint32(0x0002 | 0x0004 | 0x0008) // GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER

	r1, _, _ := procGetAdaptersAddresses.Call(
		uintptr(0), // AF_UNSPEC
		uintptr(flags),
		uintptr(0),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if r1 == 111 { // ERROR_BUFFER_OVERFLOW
		buf = make([]byte, size)
		r1, _, _ = procGetAdaptersAddresses.Call(
			uintptr(0),
			uintptr(flags),
			uintptr(0),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
		)
	}

	if r1 != 0 {
		return metaMap
	}

	curr := (*rawAdapterAddresses)(unsafe.Pointer(&buf[0]))
	for curr != nil {
		friendly := utf16PtrToString(curr.FriendlyName)
		desc := utf16PtrToString(curr.Description)
		descLower := strings.ToLower(desc)

		isWireless := curr.IfType == 71 || strings.Contains(descLower, "wireless") || strings.Contains(descLower, "wi-fi")
		isVirtual := strings.Contains(descLower, "virtual") || strings.Contains(descLower, "vmware") ||
			strings.Contains(descLower, "hyper-v") || strings.Contains(descLower, "tap") ||
			strings.Contains(descLower, "wintun") || strings.Contains(descLower, "tunnel") ||
			curr.IfType == 131 || curr.IfType == 53
		isPhysical := !isVirtual && (curr.IfType == 6 || curr.IfType == 71)

		metaMap[int(curr.IfIndex)] = &AdapterMetadata{
			FriendlyName: friendly,
			Description:  desc,
			IfType:       curr.IfType,
			IsWireless:   isWireless,
			IsPhysical:   isPhysical,
			IsVirtual:    isVirtual,
		}

		curr = curr.Next
	}

	return metaMap
}

// GetPlatformMetadata discovers platform-specific metadata for an interface on Windows.
func GetPlatformMetadata(iface net.Interface) *AdapterMetadata {
	metaMu.Lock()
	defer metaMu.Unlock()

	// Query fresh adapter metadata
	cachedWindowsMeta = queryWindowsAdapters()

	if meta, ok := cachedWindowsMeta[iface.Index]; ok {
		return meta
	}

	// Try lookup by name matching if index differs
	for _, meta := range cachedWindowsMeta {
		if strings.EqualFold(meta.FriendlyName, iface.Name) {
			return meta
		}
	}

	return nil
}
