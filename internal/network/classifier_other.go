//go:build !windows && !linux

package network

import (
	"net"
)

// GetPlatformMetadata returns nil on platforms where kernel interface metadata query is not implemented.
func GetPlatformMetadata(iface net.Interface) *AdapterMetadata {
	return nil
}
