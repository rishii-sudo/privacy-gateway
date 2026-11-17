package app

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/48sh1xbh/privacy-gateway/internal/config"
)

func newTestApp(t *testing.T) *Application {
	t.Helper()
	tempDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Storage.LogDir = filepath.Join(tempDir, "Logs")
	cfg.Storage.ReportDir = filepath.Join(tempDir, "Reports")
	cfg.Storage.RecycleBinDir = filepath.Join(tempDir, "Recycle Bin")
	cfg.Storage.BackupDir = filepath.Join(tempDir, "Backups")

	app, err := NewApplicationWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create test app: %v", err)
	}
	return app
}

func TestInteractiveMenuChoices(t *testing.T) {
	app := newTestApp(t)
	defer app.Close()

	// Test selecting Exit [4]
	input := strings.NewReader("4\n")
	var out bytes.Buffer

	if err := app.RunInteractiveStartup(input, &out); err != nil {
		t.Fatalf("RunInteractiveStartup error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "PRIVACY GATEWAY") {
		t.Errorf("output missing title banner")
	}
	if !strings.Contains(output, "Developed by 48sh1xbh") {
		t.Errorf("output missing developer attribution")
	}
	if !strings.Contains(output, "Exiting Privacy Gateway") {
		t.Errorf("output missing exit message")
	}
}

func TestDiagnosticsOutput(t *testing.T) {
	app := newTestApp(t)
	defer app.Close()

	var out bytes.Buffer
	if err := app.RunDiagnostics(&out); err != nil {
		t.Fatalf("RunDiagnostics error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "SYSTEM & NETWORK DIAGNOSTICS") {
		t.Errorf("diagnostics banner missing")
	}
	if !strings.Contains(output, "NETWORK INTERFACES") {
		t.Errorf("network interface section missing")
	}
}

func TestStatusOutput(t *testing.T) {
	app := newTestApp(t)
	defer app.Close()

	var out bytes.Buffer
	if err := app.RunStatus(&out); err != nil {
		t.Fatalf("RunStatus error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Privacy Gateway") {
		t.Errorf("status output missing app name")
	}
	if !strings.Contains(output, "48sh1xbh") {
		t.Errorf("status output missing developer name")
	}
}

func TestChecksAndReportOutput(t *testing.T) {
	app := newTestApp(t)
	defer app.Close()

	// Test text format
	var out bytes.Buffer
	if err := app.RunChecks(&out, false); err != nil {
		t.Fatalf("RunChecks error: %v", err)
	}
	if !strings.Contains(out.String(), "DISCLAIMER") {
		t.Errorf("report output missing mandatory disclaimer")
	}

	// Test JSON format
	var jsonOut bytes.Buffer
	if err := app.RunChecks(&jsonOut, true); err != nil {
		t.Fatalf("RunChecks JSON error: %v", err)
	}
	if !strings.Contains(jsonOut.String(), `"developer": "Developed by 48sh1xbh"`) {
		t.Errorf("JSON output missing developer attribution")
	}
}
