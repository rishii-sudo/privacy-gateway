package audit

import (
	"errors"
	"time"
)

var (
	// ErrNotImplemented indicates advanced security auditing is scheduled for Milestone 10.
	ErrNotImplemented = errors.New("security audit engine is scheduled for Milestone 10 (M10)")
)

// Event records an immutable security-relevant operation.
type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
	Success   bool      `json:"success"`
	Detail    string    `json:"detail"`
}

// Auditor defines the logging and integrity verification of security events.
type Auditor interface {
	RecordEvent(event Event) error
	QueryEvents(since time.Time) ([]Event, error)
}
