package tor

import (
	"errors"
	"time"
)

var (
	// ErrNotConnected indicates the controller has no active connection to a Tor control endpoint.
	ErrNotConnected = errors.New("not connected to tor control endpoint")

	// ErrAlreadyConnected indicates a connection is already open.
	ErrAlreadyConnected = errors.New("tor controller connection is already established")

	// ErrAuthFailed indicates authentication was rejected by the Tor daemon.
	ErrAuthFailed = errors.New("tor control authentication failed")

	// ErrInvalidHMAC indicates the server HMAC verification failed during SAFECOOKIE challenge.
	ErrInvalidHMAC = errors.New("safecookie server HMAC mismatch: authentication failed closed")

	// ErrInvalidCookieSize indicates the cookie file does not match the mandatory 32-byte length.
	ErrInvalidCookieSize = errors.New("invalid cookie file size: must be exactly 32 bytes")

	// ErrInvalidState indicates an operation was attempted in an invalid controller state.
	ErrInvalidState = errors.New("invalid controller state for requested operation")

	// ErrCommandTimeout indicates a Tor control command timed out waiting for reply.
	ErrCommandTimeout = errors.New("tor control command timed out")

	// ErrProtocolViolation indicates an unexpected or malformed response from the Tor daemon.
	ErrProtocolViolation = errors.New("tor control protocol violation")

	// ErrEventQueueFull indicates the asynchronous event queue dropped an event due to buffer overflow.
	ErrEventQueueFull = errors.New("tor event queue is full: dropped event")

	// ErrInspectorUnavailable indicates the pg-tor-inspector sub-process could not be executed.
	ErrInspectorUnavailable = errors.New("pg-tor-inspector component unavailable")

	// ErrClosed indicates the controller has been closed.
	ErrClosed = errors.New("tor controller is closed")

	// ErrNotImplemented indicates a feature or stub is not implemented.
	ErrNotImplemented = errors.New("tor controller method not implemented")
)

// PeerVerificationStatus describes the outcome of Unix socket peer process verification.
type PeerVerificationStatus string

const (
	PeerVerificationNone        PeerVerificationStatus = "NONE"        // No Unix socket connection has been attempted.
	PeerVerificationVerified    PeerVerificationStatus = "VERIFIED"    // Peer process credentials verified (Linux SO_PEERCRED).
	PeerVerificationUnsupported PeerVerificationStatus = "UNSUPPORTED" // Operating system does not support peer credential retrieval.
	PeerVerificationFailed      PeerVerificationStatus = "FAILED"      // Peer process credentials check failed or peer UID untrusted.
)

// MonitoringHealth represents the telemetry and event health state.
type MonitoringHealth string

const (
	MonitoringHealthNormal   MonitoringHealth = "NORMAL"
	MonitoringHealthDegraded MonitoringHealth = "DEGRADED"
)

// MonitoringStatus provides structured telemetry about event queue health and drops.
type MonitoringStatus struct {
	Health         MonitoringHealth `json:"health"` // NORMAL or DEGRADED
	DroppedEvents  uint64           `json:"dropped_events"`
	TotalEvents    uint64           `json:"total_events"`
	LastDropTime   time.Time        `json:"last_drop_time,omitempty"`
	DegradedReason string           `json:"degraded_reason,omitempty"`
}

// ControllerState represents the sequential connection and authentication state.
type ControllerState string

const (
	StateDisconnected   ControllerState = "DISCONNECTED"
	StateConnecting     ControllerState = "CONNECTING"
	StateProtocolInfo   ControllerState = "PROTOCOLINFO"
	StateChallenging    ControllerState = "CHALLENGING"
	StateAuthenticating ControllerState = "AUTHENTICATING"
	StateAuthenticated  ControllerState = "AUTHENTICATED"
	StateClosed         ControllerState = "CLOSED"
)

// BootstrapStatus represents the Tor daemon bootstrap progress.
type BootstrapStatus struct {
	Progress int       `json:"progress"` // 0 to 100
	Tag      string    `json:"tag"`
	Summary  string    `json:"summary"`
	Warning  string    `json:"warning,omitempty"`
	Ready    bool      `json:"ready"`
	Updated  time.Time `json:"updated"`
}

// Relay represents a single node within an established Tor circuit.
type Relay struct {
	Fingerprint string `json:"fingerprint"`
	Nickname    string `json:"nickname"`
}

// Circuit represents an established Tor multi-relay circuit.
type Circuit struct {
	ID         string    `json:"id"`
	Status     string    `json:"status"` // LAUNCHED, BUILT, EXTENDED, FAILED, CLOSED
	Path       []Relay   `json:"path"`
	BuildFlags []string  `json:"build_flags,omitempty"`
	Purpose    string    `json:"purpose,omitempty"`
	BuildTime  time.Time `json:"build_time"`
}

// Event represents an asynchronous notification received from the Tor daemon (650 line).
type Event struct {
	Type      string            `json:"type"` // STATUS_CLIENT, CIRC, STREAM
	Severity  string            `json:"severity,omitempty"`
	Action    string            `json:"action,omitempty"`
	Raw       string            `json:"raw"`
	Details   map[string]string `json:"details,omitempty"`
	Timestamp time.Time         `json:"timestamp"` // Captured in UTC
}

// ProtocolInfo encapsulates parameters returned by the PROTOCOLINFO command.
type ProtocolInfo struct {
	TorVersion  string   `json:"tor_version"`
	AuthMethods []string `json:"auth_methods"`
	CookieFile  string   `json:"cookie_file,omitempty"`
}

// AuthResult holds the outcome of a Tor Control authentication attempt.
type AuthResult struct {
	Success  bool   `json:"success"`
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Error    string `json:"error,omitempty"`
}
