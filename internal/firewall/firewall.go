package firewall

import (
	"errors"
)

var (
	// ErrNotImplemented indicates firewall kill switch implementation is scheduled for Milestone 4.
	ErrNotImplemented = errors.New("firewall kill switch is scheduled for Milestone 4 (M4)")
)

// Policy defines firewall behavior and state rules.
type Policy struct {
	Mode          string `json:"mode"` // "simulate", "observe", "enforce"
	BlockDefault  bool   `json:"block_default"`
	AllowLocalDNS bool   `json:"allow_local_dns"`
}

// Adapter defines the operating system firewall abstraction.
type Adapter interface {
	Name() string
	EnableKillSwitch(policy Policy) error
	DisableKillSwitch() error
	IsActive() (bool, error)
	Rollback() error
}
