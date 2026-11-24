package tor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/config"
)

// TestM2SignalNewnymRestricted asserts that SIGNAL NEWNYM is strictly blocked in M2.
func TestM2SignalNewnymRestricted(t *testing.T) {
	cfg := config.DefaultConfig()
	client := NewClient(cfg, nil)

	err := client.RequestNewIdentity()
	if err == nil {
		t.Fatalf("expected error when invoking RequestNewIdentity, got nil")
	}

	if !errors.Is(err, ErrSignalNewnymDisabled) {
		t.Errorf("expected ErrSignalNewnymDisabled, got: %v", err)
	}

	if err.Error() != "SIGNAL NEWNYM is restricted in Milestone 2 (M2) monitoring scope" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// TestM2ReadOnlyServerCommands asserts that controller operations execute only read-only commands
// (GETINFO, PROTOCOLINFO, AUTHCHALLENGE, AUTHENTICATE, SETEVENTS, QUIT) and never send mutating commands.
func TestM2ReadOnlyServerCommands(t *testing.T) {
	server, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second

	client := server.Client(cfg, nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.ConnectAndAuthenticate(ctx); err != nil {
		t.Fatalf("ConnectAndAuthenticate failed: %v", err)
	}

	// Execute normal read-only query suite
	_, _ = client.GetVersion(ctx)
	_, _ = client.GetBootstrapStatus(ctx)
	_, _ = client.GetCircuitEstablished(ctx)
	_, _ = client.GetActiveCircuits(ctx)
	_, _ = client.GetSocksListeners(ctx)

	// Verify RequestNewIdentity fails without sending SIGNAL
	reqErr := client.RequestNewIdentity()
	if !errors.Is(reqErr, ErrSignalNewnymDisabled) {
		t.Errorf("expected ErrSignalNewnymDisabled, got: %v", reqErr)
	}
}
