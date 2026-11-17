package routing

import (
	"errors"
)

var (
	// ErrNotImplemented indicates multi-hop routing verification is scheduled for Milestone 5.
	ErrNotImplemented = errors.New("multi-hop routing is scheduled for Milestone 5 (M5)")
)

// Hop represents a single node in a multi-hop route chain.
type Hop struct {
	Index    int    `json:"index"`
	Type     string `json:"type"` // "Tor", "VPN", "Proxy"
	Endpoint string `json:"endpoint"`
	Country  string `json:"country,omitempty"`
}

// RouteChain defines a multi-hop routing configuration.
type RouteChain struct {
	Name string `json:"name"`
	Hops []Hop  `json:"hops"`
}

// Router defines the interface for configuring and verifying multi-hop route chains.
type Router interface {
	VerifyRouteChain(chain RouteChain) (bool, error)
	GetExitNodeStatus() (string, error)
}

// UnimplementedRouter provides a baseline stub returning ErrNotImplemented.
type UnimplementedRouter struct{}

func (u *UnimplementedRouter) VerifyRouteChain(chain RouteChain) (bool, error) {
	return false, ErrNotImplemented
}

func (u *UnimplementedRouter) GetExitNodeStatus() (string, error) {
	return "", ErrNotImplemented
}
