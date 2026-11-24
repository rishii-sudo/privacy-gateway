package app

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/config"
	"github.com/rishii-sudo/privacy-gateway/internal/tor"
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

func TestTorCommandWithMockServer(t *testing.T) {
	server, _, err := tor.NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock tor server: %v", err)
	}
	defer server.Close()

	app := newTestApp(t)
	defer app.Close()

	app.Config.Tor.Enabled = true
	app.Config.Tor.ControlEndpoint = server.Addr()
	app.Config.Tor.CookiePath = server.CookiePath()
	app.Config.Tor.ConnectionTimeout = 2 * time.Second

	client := server.Client(app.Config, app.Logger)
	defer client.Close()

	app.SetTorClient(client)

	// 1. Tor Status
	var statusOut bytes.Buffer
	if err := app.RunTorCommand(&statusOut, []string{"status"}); err != nil {
		t.Fatalf("RunTorCommand status error: %v", err)
	}
	statusStr := statusOut.String()
	if !strings.Contains(statusStr, "TOR DAEMON & CONTROL STATUS") {
		t.Errorf("status output missing banner")
	}
	if !strings.Contains(statusStr, "SAFECOOKIE") {
		t.Errorf("status output missing SAFECOOKIE success")
	}
	if !strings.Contains(statusStr, "CAUTION: Tor control connection active") {
		t.Errorf("status output missing caution notice")
	}

	// 2. Tor Bootstrap
	var bootOut bytes.Buffer
	if err := app.RunTorCommand(&bootOut, []string{"bootstrap"}); err != nil {
		t.Fatalf("RunTorCommand bootstrap error: %v", err)
	}
	bootStr := bootOut.String()
	if !strings.Contains(bootStr, "TOR DAEMON BOOTSTRAP MONITOR") {
		t.Errorf("bootstrap output missing banner")
	}
	if !strings.Contains(bootStr, "100%") {
		t.Errorf("bootstrap output missing 100%% completion")
	}

	// 3. Tor Circuits
	var circOut bytes.Buffer
	if err := app.RunTorCommand(&circOut, []string{"circuits"}); err != nil {
		t.Fatalf("RunTorCommand circuits error: %v", err)
	}
	circStr := circOut.String()
	if !strings.Contains(circStr, "TOR CIRCUIT STATUS & RELAYS") {
		t.Errorf("circuits output missing banner")
	}
	if !strings.Contains(circStr, "Active Circuits") {
		t.Errorf("circuits output missing active circuits")
	}

	// 4. Tor Events (short duration)
	var eventsOut bytes.Buffer
	if err := app.RunTorCommand(&eventsOut, []string{"events", "100ms"}); err != nil {
		t.Fatalf("RunTorCommand events error: %v", err)
	}
	if !strings.Contains(eventsOut.String(), "TOR ASYNCHRONOUS EVENT STREAM") {
		t.Errorf("events output missing banner")
	}

	// 5. Tor Diagnostics
	var diagOut bytes.Buffer
	if err := app.RunTorCommand(&diagOut, []string{"diagnostics"}); err != nil {
		t.Fatalf("RunTorCommand diagnostics error: %v", err)
	}
	diagStr := diagOut.String()
	if !strings.Contains(diagStr, "TOR COMPREHENSIVE DIAGNOSTICS") {
		t.Errorf("diagnostics output missing banner")
	}
	if !strings.Contains(diagStr, "TOR_CONTROL_AUTH") {
		t.Errorf("diagnostics output missing TOR_CONTROL_AUTH evaluation")
	}

	// 6. Unknown subcommand / help
	var helpOut bytes.Buffer
	if err := app.RunTorCommand(&helpOut, []string{"unknown_cmd"}); err != nil {
		t.Fatalf("RunTorCommand help error: %v", err)
	}
	if !strings.Contains(helpOut.String(), "Available subcommands:") {
		t.Errorf("help output missing subcommands list")
	}
}

func TestTorCLIRestrictsMutatingCommands(t *testing.T) {
	app := newTestApp(t)
	defer app.Close()

	mutatingCommands := []string{"newnym", "signal", "setconf", "resetconf", "saveconf"}
	for _, cmd := range mutatingCommands {
		var out bytes.Buffer
		err := app.RunTorCommand(&out, []string{cmd})
		if err != nil {
			t.Errorf("expected no fatal panic on unknown command %q: %v", cmd, err)
		}
		outStr := out.String()
		if !strings.Contains(outStr, fmt.Sprintf("Unknown Tor subcommand %q", cmd)) {
			t.Errorf("expected command %q to be rejected as unknown, got: %s", cmd, outStr)
		}
	}
}

func TestApplicationCloseShutdownOrderAndIdempotency(t *testing.T) {
	app := newTestApp(t)

	// Create and attach a real Tor client
	cfg := config.DefaultConfig()
	client := tor.NewClient(cfg, app.Logger)
	app.SetTorClient(client)

	// Verify client is not closed yet
	if client.State() == tor.StateClosed {
		t.Fatalf("expected client to not be closed yet")
	}

	// First Close call: should close Tor client before logger and succeed cleanly
	err1 := app.Close()
	if err1 != nil {
		t.Fatalf("unexpected error on first Close(): %v", err1)
	}

	// Verify Tor client state transitioned to Closed
	if client.State() != tor.StateClosed {
		t.Errorf("expected client state to be Closed after app.Close(), got: %v", client.State())
	}

	// Second Close call: must be idempotent and return identical error (nil)
	err2 := app.Close()
	if err2 != nil {
		t.Errorf("unexpected error on second Close(): %v", err2)
	}

	// Third Close call: still idempotent
	err3 := app.Close()
	if err3 != nil {
		t.Errorf("unexpected error on third Close(): %v", err3)
	}
}

func TestApplicationCloseRepeatedCallsReturnIdenticalResult(t *testing.T) {
	app := newTestApp(t)

	cfg := config.DefaultConfig()
	client := tor.NewClient(cfg, app.Logger)
	app.SetTorClient(client)

	firstErr := app.Close()
	for i := 0; i < 5; i++ {
		repeatErr := app.Close()
		if repeatErr != firstErr {
			t.Errorf("expected idempotent error %v on repeat call %d, got %v", firstErr, i, repeatErr)
		}
	}
}

func TestTorCLICommandFailuresReturnNonNilError(t *testing.T) {
	app := newTestApp(t)
	defer app.Close()

	// Configure an endpoint where no Tor daemon is running
	app.Config.Tor.ControlEndpoint = "127.0.0.1:19999"
	app.Config.Tor.ConnectionTimeout = 200 * time.Millisecond

	// 1. Status failure returns non-nil error
	var out bytes.Buffer
	if err := app.RunTorCommand(&out, []string{"status"}); err == nil {
		t.Errorf("expected non-nil error on failed Tor status connection, got nil")
	}

	// 2. Bootstrap failure returns non-nil error
	out.Reset()
	if err := app.RunTorCommand(&out, []string{"bootstrap"}); err == nil {
		t.Errorf("expected non-nil error on failed Tor bootstrap connection, got nil")
	}

	// 3. Circuits failure returns non-nil error
	out.Reset()
	if err := app.RunTorCommand(&out, []string{"circuits"}); err == nil {
		t.Errorf("expected non-nil error on failed Tor circuits connection, got nil")
	}

	// 4. Events failure returns non-nil error
	out.Reset()
	if err := app.RunTorCommand(&out, []string{"events", "100ms"}); err == nil {
		t.Errorf("expected non-nil error on failed Tor events connection, got nil")
	}
}
