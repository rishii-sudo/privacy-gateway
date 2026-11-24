package tor

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
)

// EndpointCandidate describes a discovered local Tor ControlPort or socket.
type EndpointCandidate struct {
	Network  string `json:"network"`  // "tcp" or "unix"
	Endpoint string `json:"endpoint"` // e.g. "127.0.0.1:9051"
	Active   bool   `json:"active"`
}

// DiscoverLocalEndpoints probes common local loopback endpoints read-only.
// It strictly never scans remote or external networks.
func DiscoverLocalEndpoints(timeout time.Duration) []EndpointCandidate {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}

	var candidates []EndpointCandidate

	// 1. Common TCP loopback ports
	tcpPorts := []string{"127.0.0.1:9051", "127.0.0.1:9151", "[::1]:9051", "[::1]:9151"}
	for _, ep := range tcpPorts {
		active := probeEndpoint("tcp", ep, timeout)
		candidates = append(candidates, EndpointCandidate{
			Network:  "tcp",
			Endpoint: ep,
			Active:   active,
		})
	}

	// 2. Common Unix domain sockets (Linux / BSD / macOS only)
	if runtime.GOOS != "windows" {
		unixSockets := []string{
			"/var/run/tor/control",
			"/run/tor/control",
			"/var/lib/tor/control",
		}
		for _, sock := range unixSockets {
			if _, err := os.Stat(sock); err == nil {
				active := probeEndpoint("unix", sock, timeout)
				candidates = append(candidates, EndpointCandidate{
					Network:  "unix",
					Endpoint: sock,
					Active:   active,
				})
			}
		}
	}

	return candidates
}

// FindFirstActiveEndpoint searches local candidates and returns the first reachable endpoint.
func FindFirstActiveEndpoint(timeout time.Duration) (network, endpoint string, err error) {
	candidates := DiscoverLocalEndpoints(timeout)
	for _, c := range candidates {
		if c.Active {
			return c.Network, c.Endpoint, nil
		}
	}
	return "", "", fmt.Errorf("no active local tor control endpoints discovered")
}

func probeEndpoint(netType, address string, timeout time.Duration) bool {
	conn, err := net.DialTimeout(netType, address, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
