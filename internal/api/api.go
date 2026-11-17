package api

import (
	"errors"
)

var (
	// ErrNotImplemented indicates the local authenticated API server is scheduled for Milestone 9.
	ErrNotImplemented = errors.New("local API server is scheduled for Milestone 9 (M9)")
)

// Server defines the contract for local Go API integration serving the desktop GUI.
type Server interface {
	Start(bindAddress string) error
	Stop() error
	IsRunning() bool
}
