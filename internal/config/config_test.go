package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig failed validation: %v", err)
	}

	if cfg.App.Developer != "48sh1xbh" {
		t.Errorf("expected developer 48sh1xbh, got %s", cfg.App.Developer)
	}
	if cfg.Telemetry.Enabled {
		t.Errorf("telemetry must be disabled by default")
	}
	if cfg.Firewall.Mode != "simulate" {
		t.Errorf("firewall mode must default to simulate, got %s", cfg.Firewall.Mode)
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	cfg := DefaultConfig()
	cfg.App.Environment = "research"
	cfg.Network.ProbeTimeout = 10 * time.Second

	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load saved config: %v", err)
	}

	if loaded.App.Environment != "research" {
		t.Errorf("expected environment 'research', got %s", loaded.App.Environment)
	}
	if loaded.Network.ProbeTimeout != 10*time.Second {
		t.Errorf("expected probe timeout 10s, got %v", loaded.Network.ProbeTimeout)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name: "empty app name",
			modify: func(c *Config) {
				c.App.Name = ""
			},
			wantErr: true,
		},
		{
			name: "negative timeout",
			modify: func(c *Config) {
				c.Network.ProbeTimeout = -1 * time.Second
			},
			wantErr: true,
		},
		{
			name: "excessive timeout",
			modify: func(c *Config) {
				c.Network.ProbeTimeout = 70 * time.Second
			},
			wantErr: true,
		},
		{
			name: "invalid log level",
			modify: func(c *Config) {
				c.Logging.Level = "INVALID"
			},
			wantErr: true,
		},
		{
			name: "invalid firewall mode",
			modify: func(c *Config) {
				c.Firewall.Mode = "aggressive"
			},
			wantErr: true,
		},
		{
			name: "telemetry disabled with destination set",
			modify: func(c *Config) {
				c.Telemetry.Enabled = false
				c.Telemetry.Destination = "https://example.com/telemetry"
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestLoadOrDefault(t *testing.T) {
	// Non-existent path returns default config
	cfg, err := LoadOrDefault("non_existent_path.yaml")
	if err != nil {
		t.Fatalf("expected no error for non-existent file, got %v", err)
	}
	if cfg.App.Name != "Privacy Gateway" {
		t.Errorf("unexpected app name: %s", cfg.App.Name)
	}

	// Corrupted file returns error
	tempDir := t.TempDir()
	badFile := filepath.Join(tempDir, "bad.yaml")
	if err := os.WriteFile(badFile, []byte("app:\n  name: [invalid"), 0600); err != nil {
		t.Fatalf("failed to write bad file: %v", err)
	}

	_, err = LoadOrDefault(badFile)
	if err == nil {
		t.Fatalf("expected error for malformed yaml, got nil")
	}
}
