//go:build linux

package network

import (
	"net"
	"os"
	"path/filepath"
	"strings"
)

// GetPlatformMetadata discovers platform-specific metadata for an interface on Linux.
func GetPlatformMetadata(iface net.Interface) *AdapterMetadata {
	meta := &AdapterMetadata{
		FriendlyName: iface.Name,
	}

	sysNetDir := filepath.Join("/sys/class/net", iface.Name)

	// Check if interface directory exists
	if _, err := os.Stat(sysNetDir); err != nil {
		return nil
	}

	// 1. Wireless check: presence of wireless or phy80211 subdirectory
	wirelessDir := filepath.Join(sysNetDir, "wireless")
	phyDir := filepath.Join(sysNetDir, "phy80211")
	if _, err := os.Stat(wirelessDir); err == nil {
		meta.IsWireless = true
	} else if _, err := os.Stat(phyDir); err == nil {
		meta.IsWireless = true
	}

	// 2. Physical hardware check: /sys/class/net/<name>/device symlink exists for physical hardware
	devicePath := filepath.Join(sysNetDir, "device")
	if _, err := os.Stat(devicePath); err == nil {
		// Hardware device exists
		driverPath := filepath.Join(devicePath, "driver")
		if target, err := os.Readlink(driverPath); err == nil {
			driverName := filepath.Base(target)
			meta.Driver = driverName
			meta.Description = "Driver: " + driverName

			// Check if driver is a VM driver (vmxnet, virtio, vbox)
			driverLower := strings.ToLower(driverName)
			if strings.Contains(driverLower, "vmxnet") || strings.Contains(driverLower, "vmnet") ||
				strings.Contains(driverLower, "virtio") || strings.Contains(driverLower, "vbox") {
				meta.IsVirtual = true
				meta.IsPhysical = false
			} else {
				meta.IsPhysical = true
			}
		} else {
			meta.IsPhysical = true
		}
	} else {
		// Virtual/software interface (no backing hardware device)
		meta.IsVirtual = true
		meta.IsPhysical = false
	}

	return meta
}
