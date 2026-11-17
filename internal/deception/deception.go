package deception

import (
	"errors"
	"time"
)

var (
	// ErrNotImplemented indicates honeypot and deception lab is scheduled for Milestone 8.
	ErrNotImplemented = errors.New("deception lab is scheduled for Milestone 8 (M8)")
)

// DecoyType defines the mock protocol service.
type DecoyType string

const (
	DecoySSH  DecoyType = "ssh"
	DecoyHTTP DecoyType = "http"
	DecoyAPI  DecoyType = "api"
)

// DecoyEvent represents an observed interaction on an isolated decoy service.
type DecoyEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	DecoyType  DecoyType `json:"decoy_type"`
	SourceIP   string    `json:"source_ip"`
	SourcePort int       `json:"source_port"`
	Payload    string    `json:"payload"`
}

// Lab defines methods for starting and auditing isolated decoy environments.
type Lab interface {
	StartDecoy(decoyType DecoyType, bindAddr string) error
	StopDecoy(decoyType DecoyType) error
	GetEvents() ([]DecoyEvent, error)
}

// UnimplementedLab provides a baseline stub returning ErrNotImplemented.
type UnimplementedLab struct{}

func (u *UnimplementedLab) StartDecoy(decoyType DecoyType, bindAddr string) error {
	return ErrNotImplemented
}

func (u *UnimplementedLab) StopDecoy(decoyType DecoyType) error {
	return ErrNotImplemented
}

func (u *UnimplementedLab) GetEvents() ([]DecoyEvent, error) {
	return nil, ErrNotImplemented
}
