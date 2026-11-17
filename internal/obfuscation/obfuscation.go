package obfuscation

import (
	"errors"
)

var (
	// ErrNotImplemented indicates transport obfuscation is scheduled for Milestone 6.
	ErrNotImplemented = errors.New("transport obfuscation is scheduled for Milestone 6 (M6)")
)

// TransportProtocol denotes supported obfuscation mechanisms.
type TransportProtocol string

const (
	ProtocolOBFS4       TransportProtocol = "obfs4"
	ProtocolTorBridge   TransportProtocol = "tor_bridge"
	ProtocolVPNScramble TransportProtocol = "vpn_scramble"
)

// Config defines parameters for an obfuscated transport.
type Config struct {
	Protocol TransportProtocol `json:"protocol"`
	Endpoint string            `json:"endpoint"`
	Cert     string            `json:"cert,omitempty"`
	IATMode  int               `json:"iat_mode,omitempty"`
}

// Obfuscator defines the interface for managing transport disguise mechanisms.
type Obfuscator interface {
	ValidateConfig(cfg Config) error
	CheckHealth(cfg Config) (bool, error)
}

// UnimplementedObfuscator provides a baseline stub returning ErrNotImplemented.
type UnimplementedObfuscator struct{}

func (u *UnimplementedObfuscator) ValidateConfig(cfg Config) error {
	return ErrNotImplemented
}

func (u *UnimplementedObfuscator) CheckHealth(cfg Config) (bool, error) {
	return false, ErrNotImplemented
}
