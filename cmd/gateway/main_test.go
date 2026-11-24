package main

import (
	"path/filepath"
	"testing"

	"github.com/rishii-sudo/privacy-gateway/internal/app"
	"github.com/rishii-sudo/privacy-gateway/internal/config"
	"github.com/rishii-sudo/privacy-gateway/internal/tor"
)

func TestCLIRouting(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Storage.LogDir = filepath.Join(tempDir, "Logs")
	cfg.Storage.ReportDir = filepath.Join(tempDir, "Reports")
	cfg.Storage.RecycleBinDir = filepath.Join(tempDir, "Recycle Bin")
	cfg.Storage.BackupDir = filepath.Join(tempDir, "Backups")

	mockServer, _, err := tor.NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock tor server: %v", err)
	}
	defer mockServer.Close()

	cfg.Tor.Enabled = true
	cfg.Tor.ControlEndpoint = mockServer.Addr()
	cfg.Tor.CookiePath = mockServer.CookiePath()

	application, err := app.NewApplicationWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create test application: %v", err)
	}
	defer application.Close()

	torClient := mockServer.Client(cfg, application.Logger)
	defer torClient.Close()
	application.SetTorClient(torClient)

	testCases := []struct {
		name string
		args []string
	}{
		{"version flag", []string{"--version"}},
		{"diagnostics flag", []string{"--diagnostics"}},
		{"help flag", []string{"--help"}},
		{"gui flag", []string{"--gui"}},
		{"status subcommand", []string{"status"}},
		{"check subcommand", []string{"check"}},
		{"report subcommand json", []string{"report", "--json"}},
		{"tor status subcommand", []string{"tor", "status"}},
		{"tor bootstrap subcommand", []string{"tor", "bootstrap"}},
		{"tor circuits subcommand", []string{"tor", "circuits"}},
		{"tor diagnostics subcommand", []string{"tor", "diagnostics"}},
		{"tor help subcommand", []string{"tor", "help"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := runWithApp(tc.args, application); err != nil {
				t.Fatalf("runWithApp(%v) failed with: %v", tc.args, err)
			}
		})
	}
}

func TestCLITorDaemonFailureReturnsNonNilError(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Storage.LogDir = filepath.Join(tempDir, "Logs")
	cfg.Storage.ReportDir = filepath.Join(tempDir, "Reports")
	cfg.Storage.RecycleBinDir = filepath.Join(tempDir, "Recycle Bin")
	cfg.Storage.BackupDir = filepath.Join(tempDir, "Backups")
	cfg.Tor.ControlEndpoint = "127.0.0.1:19999"

	application, err := app.NewApplicationWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create test application: %v", err)
	}
	defer application.Close()

	torCommands := [][]string{
		{"tor", "status"},
		{"tor", "bootstrap"},
		{"tor", "circuits"},
	}

	for _, cmd := range torCommands {
		if err := runWithApp(cmd, application); err == nil {
			t.Errorf("expected runWithApp(%v) to return non-nil error when Tor is disconnected, got nil", cmd)
		}
	}
}

func TestContainsFlag(t *testing.T) {
	args := []string{"--verbose", "--json", "-o"}
	if !containsFlag(args, "--json") {
		t.Errorf("expected containsFlag to return true for --json")
	}
	if containsFlag(args, "--missing") {
		t.Errorf("expected containsFlag to return false for --missing")
	}
}
