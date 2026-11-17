package tor

import (
	"errors"
	"time"
)

var (
	// ErrNotImplemented indicates the Tor control protocol integration is scheduled for Milestone 2.
	ErrNotImplemented = errors.New("tor integration is scheduled for Milestone 2 (M2)")
)

// BootstrapStatus represents the Tor daemon bootstrap progress.
type BootstrapStatus struct {
	Progress int       `json:"progress"` // 0 to 100
	Phase    string    `json:"phase"`
	Summary  string    `json:"summary"`
	Ready    bool      `json:"ready"`
	Updated  time.Time `json:"updated"`
}

// Circuit represents an established Tor multi-relay circuit.
type Circuit struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Relays    []string  `json:"relays"`
	BuildTime time.Time `json:"build_time"`
}

// Controller defines the contract for communicating with the local Tor daemon
// via the Tor Control Protocol.
type Controller interface {
	Connect(controlAddr, password string) error
	GetBootstrapStatus() (*BootstrapStatus, error)
	GetActiveCircuits() ([]Circuit, error)
	RequestNewIdentity() error
	Close() error
}

// UnimplementedController provides a baseline stub returning ErrNotImplemented.
type UnimplementedController struct{}

func (u *UnimplementedController) Connect(controlAddr, password string) error {
	return ErrNotImplemented
}

func (u *UnimplementedController) GetBootstrapStatus() (*BootstrapStatus, error) {
	return nil, ErrNotImplemented
}

func (u *UnimplementedController) GetActiveCircuits() ([]Circuit, error) {
	return nil, ErrNotImplemented
}

func (u *UnimplementedController) RequestNewIdentity() error {
	return ErrNotImplemented
}

func (u *UnimplementedController) Close() error {
	return nil
}
