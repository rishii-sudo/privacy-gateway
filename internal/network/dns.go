package network

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

// DNSConfig represents discovered or configured DNS resolvers.
type DNSConfig struct {
	Servers         []string `json:"servers"`
	Source          string   `json:"source"`            // "system_resolv_conf", "configured", "default"
	HasEncryptedDNS bool     `json:"has_encrypted_dns"` // Status heuristic
	SearchDomains   []string `json:"search_domains,omitempty"`
}

// DiscoverDNSResolvers attempts read-only discovery of configured DNS servers on the system.
func DiscoverDNSResolvers(fallback []string) DNSConfig {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		cfg, err := parseResolvConf("/etc/resolv.conf")
		if err == nil && len(cfg.Servers) > 0 {
			return cfg
		}
	}

	// On Windows or if /etc/resolv.conf is unavailable, use the provided fallback/configured servers
	if len(fallback) > 0 {
		return DNSConfig{
			Servers: fallback,
			Source:  "configured",
		}
	}

	return DNSConfig{
		Servers: []string{"1.1.1.1", "9.9.9.9"},
		Source:  "default",
	}
}

// parseResolvConf reads standard UNIX resolver configuration safely.
func parseResolvConf(path string) (DNSConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return DNSConfig{}, err
	}
	defer file.Close()

	var servers []string
	var search []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			switch parts[0] {
			case "nameserver":
				servers = append(servers, parts[1])
			case "search", "domain":
				search = append(search, parts[1:]...)
			}
		}
	}

	return DNSConfig{
		Servers:       servers,
		SearchDomains: search,
		Source:        "system_resolv_conf",
	}, scanner.Err()
}
