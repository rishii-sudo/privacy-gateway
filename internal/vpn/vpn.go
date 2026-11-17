package vpn

import (
	"errors"
	"time"
)

var (
	// ErrNotImplemented indicates VPN monitoring and profiles are scheduled for Milestone 3.
	ErrNotImplemented = errors.New("vpn integration is scheduled for Milestone 3 (M3)")
)

// TunnelStatus represents the observed state of an active VPN tunnel.
type TunnelStatus struct {
	Connected      bool          `json:"connected"`
	InterfaceName  string        `json:"interface_name"`
	TunnelProtocol string        `json:"protocol"` // "WireGuard", "OpenVPN", etc.
	AssignedIP     string        `json:"assigned_ip"`
	GatewayIP      string        `json:"gateway_ip"`
	Uptime         time.Duration `json:"uptime"`
}

// Manager defines the interface for VPN interface discovery and state monitoring.
type Manager interface {
	DetectVPNInterfaces() ([]string, error)
	GetTunnelStatus() (*TunnelStatus, error)
	VerifyTunnelRoute() (bool, error)
}

// UnimplementedManager provides a baseline stub returning ErrNotImplemented.
type UnimplementedManager struct{}

func (u *UnimplementedManager) DetectVPNInterfaces() ([]string, error) {
	return nil, ErrNotImplemented
}

func (u *UnimplementedManager) GetTunnelStatus() (*TunnelStatus, error) {
	return nil, ErrNotImplemented
}

func (u *UnimplementedManager) VerifyTunnelRoute() (bool, error) {
	return false, ErrNotImplemented
}
