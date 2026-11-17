package main

import (
	"path/filepath"
	"testing"

	"github.com/48sh1xbh/privacy-gateway/internal/app"
	"github.com/48sh1xbh/privacy-gateway/internal/config"
)

func TestCLIRouting(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Storage.LogDir = filepath.Join(tempDir, "Logs")
	cfg.Storage.ReportDir = filepath.Join(tempDir, "Reports")
	cfg.Storage.RecycleBinDir = filepath.Join(tempDir, "Recycle Bin")
	cfg.Storage.BackupDir = filepath.Join(tempDir, "Backups")

	application, err := app.NewApplicationWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create test application: %v", err)
	}
	defer application.Close()

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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := runWithApp(tc.args, application); err != nil {
				t.Fatalf("runWithApp(%v) failed with: %v", tc.args, err)
			}
		})
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
