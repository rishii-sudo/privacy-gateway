package tor

import (
	"context"
	"fmt"
)

var (
	// ErrSignalNewnymDisabled confirms SIGNAL NEWNYM is restricted in M2.
	ErrSignalNewnymDisabled = fmt.Errorf("SIGNAL NEWNYM is restricted in Milestone 2 (M2) monitoring scope")
)

// Controller defines the high-level contract for communicating with the local Tor daemon.
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

// Ensure Client can satisfy Controller through compatibility adapters if needed.
func (c *Client) RequestNewIdentity() error {
	return ErrSignalNewnymDisabled
}

func (c *Client) GetBootstrapStatusLegacy() (*BootstrapStatus, error) {
	return c.GetBootstrapStatus(context.Background())
}

func (c *Client) GetActiveCircuitsLegacy() ([]Circuit, error) {
	return c.GetActiveCircuits(context.Background())
}
