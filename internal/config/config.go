package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration for Privacy Gateway.
type Config struct {
	App       AppConfig       `yaml:"app"`
	Network   NetworkConfig   `yaml:"network"`
	Tor       TorConfig       `yaml:"tor"`
	Logging   LoggingConfig   `yaml:"logging"`
	Storage   StorageConfig   `yaml:"storage"`
	Firewall  FirewallConfig  `yaml:"firewall"`
	Privacy   PrivacyConfig   `yaml:"privacy"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
}

// AppConfig defines application-level metadata and interface defaults.
type AppConfig struct {
	Name        string `yaml:"name"`
	Developer   string `yaml:"developer"`
	Version     string `yaml:"version"`
	Environment string `yaml:"environment"` // "development", "production", "research"
}

// NetworkConfig controls network monitoring and discovery parameters.
type NetworkConfig struct {
	ProbeTimeout             time.Duration `yaml:"probe_timeout"`
	EnableIPv6               bool          `yaml:"enable_ipv6"`
	DnsServers               []string      `yaml:"dns_servers"`
	IgnoreLoopback           bool          `yaml:"ignore_loopback"`
	VirtualInterfacePrefixes []string      `yaml:"virtual_interface_prefixes"`
}

// TorConfig defines local Tor daemon connection and Control Protocol parameters.
type TorConfig struct {
	Enabled                 bool          `yaml:"enabled"`
	ControlEndpoint         string        `yaml:"control_endpoint"`
	NetworkMode             string        `yaml:"network_mode"` // "tcp" or "unix"
	ConnectionTimeout       time.Duration `yaml:"connection_timeout"`
	AuthPreference          string        `yaml:"auth_preference"` // "safecookie"
	CookiePath              string        `yaml:"cookie_path"`
	EventSubscriptions      []string      `yaml:"event_subscriptions"`
	ReconnectAttempts       int           `yaml:"reconnect_attempts"`
	ReconnectBackoff        time.Duration `yaml:"reconnect_backoff"`
	EventQueueLimit         int           `yaml:"event_queue_limit"`
	InspectorPath           string        `yaml:"inspector_path"`
	InspectorTimeout        time.Duration `yaml:"inspector_timeout"`
	MaxProtocolMsgSize      int           `yaml:"max_protocol_msg_size"`
	RequirePeerVerification bool          `yaml:"require_peer_verification"`
}

// LoggingConfig configures structured local logging.
type LoggingConfig struct {
	Level           string `yaml:"level"` // DEBUG, INFO, WARN, ERROR, AUDIT
	LogToConsole    bool   `yaml:"log_to_console"`
	LogToFile       bool   `yaml:"log_to_file"`
	Filename        string `yaml:"filename"`
	RedactSensitive bool   `yaml:"redact_sensitive"`
}

// StorageConfig defines local working directories.
type StorageConfig struct {
	LogDir        string `yaml:"log_dir"`
	ReportDir     string `yaml:"report_dir"`
	RecycleBinDir string `yaml:"recycle_bin_dir"`
	BackupDir     string `yaml:"backup_dir"`
}

// FirewallConfig defines firewall adapter behavior.
type FirewallConfig struct {
	Mode          string `yaml:"mode"` // "simulate" (default), "enforce"
	DefaultBlock  bool   `yaml:"default_block"`
	AllowLocalDNS bool   `yaml:"allow_local_dns"`
}

// PrivacyConfig defines privacy check parameters.
type PrivacyConfig struct {
	StrictInterfaceCheck bool `yaml:"strict_interface_check"`
	WarnOnIPv6           bool `yaml:"warn_on_ipv6"`
	WarnOnHostnameLeak   bool `yaml:"warn_on_hostname_leak"`
}

// TelemetryConfig defines diagnostic telemetry options.
// Telemetry is local-only and disabled by default.
type TelemetryConfig struct {
	Enabled        bool   `yaml:"enabled"`
	AllowAnonymous bool   `yaml:"allow_anonymous"`
	Destination    string `yaml:"destination"`
}

// DefaultConfig returns a secure, production-safe baseline configuration.
func DefaultConfig() *Config {
	return &Config{
		App: AppConfig{
			Name:        "Privacy Gateway",
			Developer:   "48sh1xbh",
			Version:     "0.2.0-m2",
			Environment: "production",
		},
		Network: NetworkConfig{
			ProbeTimeout:   5 * time.Second,
			EnableIPv6:     false,
			DnsServers:     []string{"1.1.1.1", "9.9.9.9"},
			IgnoreLoopback: true,
			VirtualInterfacePrefixes: []string{
				"tun", "tap", "wg", "tailscale", "proton", "openvpn", "ppp",
			},
		},
		Tor: TorConfig{
			Enabled:                 false, // disabled by default until explicitly enabled
			ControlEndpoint:         "127.0.0.1:9051",
			NetworkMode:             "tcp",
			ConnectionTimeout:       5 * time.Second,
			AuthPreference:          "safecookie",
			CookiePath:              "",
			EventSubscriptions:      []string{"STATUS_CLIENT", "CIRC", "STREAM"},
			ReconnectAttempts:       3,
			ReconnectBackoff:        1 * time.Second,
			EventQueueLimit:         1000,
			InspectorPath:           "pg-tor-inspector.exe",
			InspectorTimeout:        2 * time.Second,
			MaxProtocolMsgSize:      65536,
			RequirePeerVerification: false,
		},
		Logging: LoggingConfig{
			Level:           "INFO",
			LogToConsole:    true,
			LogToFile:       true,
			Filename:        "privacy-gateway.log",
			RedactSensitive: true,
		},
		Storage: StorageConfig{
			LogDir:        "Logs",
			ReportDir:     "Reports",
			RecycleBinDir: "Recycle Bin",
			BackupDir:     "Backups",
		},
		Firewall: FirewallConfig{
			Mode:          "simulate", // Never silently enforce; simulate by default
			DefaultBlock:  false,
			AllowLocalDNS: true,
		},
		Privacy: PrivacyConfig{
			StrictInterfaceCheck: true,
			WarnOnIPv6:           true,
			WarnOnHostnameLeak:   true,
		},
		Telemetry: TelemetryConfig{
			Enabled:        false, // Explicit opt-in only; never default to true
			AllowAnonymous: false,
			Destination:    "",
		},
	}
}

// LoadConfig loads and parses a YAML configuration file from path.
// If the path does not exist, an error is returned.
func LoadConfig(path string) (*Config, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", cleanPath, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config %q: %w", cleanPath, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// LoadOrDefault attempts to load the config from path, or returns DefaultConfig if not found.
func LoadOrDefault(path string) (*Config, error) {
	if path == "" {
		cfg := DefaultConfig()
		return cfg, cfg.Validate()
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := DefaultConfig()
		return cfg, cfg.Validate()
	}
	return LoadConfig(path)
}

// Save writes the configuration to the specified YAML file path.
func (c *Config) Save(path string) error {
	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create config directory %q: %w", dir, err)
		}
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config to yaml: %w", err)
	}

	if err := os.WriteFile(cleanPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file %q: %w", cleanPath, err)
	}
	return nil
}

// Validate verifies that configuration settings adhere to safety invariants.
func (c *Config) Validate() error {
	if c.App.Name == "" {
		return fmt.Errorf("app.name must not be empty")
	}
	if c.App.Developer == "" {
		return fmt.Errorf("app.developer must not be empty")
	}
	if c.Network.ProbeTimeout <= 0 {
		return fmt.Errorf("network.probe_timeout must be greater than zero")
	}
	if c.Network.ProbeTimeout > 60*time.Second {
		return fmt.Errorf("network.probe_timeout cannot exceed 60 seconds")
	}

	// Tor configuration validation
	if c.Tor.ConnectionTimeout <= 0 {
		return fmt.Errorf("tor.connection_timeout must be greater than zero")
	}
	if c.Tor.ConnectionTimeout > 60*time.Second {
		return fmt.Errorf("tor.connection_timeout cannot exceed 60 seconds")
	}
	if c.Tor.NetworkMode != "" && c.Tor.NetworkMode != "tcp" && c.Tor.NetworkMode != "unix" {
		return fmt.Errorf("invalid tor.network_mode %q: must be tcp or unix", c.Tor.NetworkMode)
	}
	if c.Tor.AuthPreference != "" && !strings.EqualFold(c.Tor.AuthPreference, "safecookie") {
		return fmt.Errorf("invalid tor.auth_preference %q: only safecookie is supported (silent downgrades prohibited)", c.Tor.AuthPreference)
	}

	// Validate Tor Control Endpoint
	if c.Tor.NetworkMode == "unix" {
		trimmed := strings.TrimSpace(c.Tor.ControlEndpoint)
		if trimmed == "" {
			return fmt.Errorf("tor.control_endpoint must not be empty for unix mode")
		}
		if strings.Contains(trimmed, "\x00") {
			return fmt.Errorf("invalid tor.control_endpoint: unix socket path contains null byte")
		}
		clean := filepath.Clean(trimmed)
		if !filepath.IsAbs(clean) && !strings.HasPrefix(clean, "/") && !strings.HasPrefix(clean, "\\") {
			return fmt.Errorf("invalid tor.control_endpoint: unix socket path must be absolute, got %q", c.Tor.ControlEndpoint)
		}
	} else {
		// Default is TCP mode
		if strings.TrimSpace(c.Tor.ControlEndpoint) == "" {
			return fmt.Errorf("tor.control_endpoint must not be empty for tcp mode")
		}
		host, port, err := net.SplitHostPort(c.Tor.ControlEndpoint)
		if err != nil {
			return fmt.Errorf("invalid tor.control_endpoint %q: must be valid host:port format: %w", c.Tor.ControlEndpoint, err)
		}
		if strings.TrimSpace(port) == "" {
			return fmt.Errorf("invalid tor.control_endpoint %q: missing port", c.Tor.ControlEndpoint)
		}
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("invalid tor.control_endpoint %q: port must be a number between 1 and 65535", c.Tor.ControlEndpoint)
		}
		ip := net.ParseIP(host)
		isLoopback := (ip != nil && ip.IsLoopback()) || strings.EqualFold(host, "localhost")
		if !isLoopback {
			return fmt.Errorf("tor.control_endpoint must be a local loopback address: got %q", c.Tor.ControlEndpoint)
		}
	}

	if c.Tor.EventQueueLimit <= 0 {
		return fmt.Errorf("tor.event_queue_limit must be greater than zero")
	}
	if c.Tor.EventQueueLimit > 10000 {
		return fmt.Errorf("tor.event_queue_limit cannot exceed safe maximum of 10000: got %d", c.Tor.EventQueueLimit)
	}
	if c.Tor.MaxProtocolMsgSize <= 0 {
		return fmt.Errorf("tor.max_protocol_msg_size must be greater than zero")
	}
	if c.Tor.MaxProtocolMsgSize > 65536 {
		return fmt.Errorf("tor.max_protocol_msg_size cannot exceed 65536 bytes: got %d", c.Tor.MaxProtocolMsgSize)
	}

	validLevels := map[string]bool{
		"DEBUG": true, "INFO": true, "WARN": true, "ERROR": true, "AUDIT": true,
	}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("invalid logging.level %q: must be DEBUG, INFO, WARN, ERROR, or AUDIT", c.Logging.Level)
	}

	validModes := map[string]bool{
		"simulate": true, "observe": true, "enforce": true,
	}
	if !validModes[c.Firewall.Mode] {
		return fmt.Errorf("invalid firewall.mode %q: must be simulate, observe, or enforce", c.Firewall.Mode)
	}

	if c.Storage.LogDir == "" {
		return fmt.Errorf("storage.log_dir must not be empty")
	}
	if c.Storage.ReportDir == "" {
		return fmt.Errorf("storage.report_dir must not be empty")
	}
	if c.Storage.RecycleBinDir == "" {
		return fmt.Errorf("storage.recycle_bin_dir must not be empty")
	}

	// Telemetry safety checks: no destination allowed if telemetry is disabled
	if !c.Telemetry.Enabled && c.Telemetry.Destination != "" {
		return fmt.Errorf("telemetry.destination must be empty when telemetry is disabled")
	}

	return nil
}
