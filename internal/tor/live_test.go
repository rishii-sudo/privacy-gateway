package tor

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/config"
)

// TestLiveTorDaemonIntegration tests against a live local Tor daemon if one is running on loopback.
// If no Tor daemon is running, it skips gracefully and logs the absence clearly.
func TestLiveTorDaemonIntegration(t *testing.T) {
	endpoints := []string{"127.0.0.1:9051", "127.0.0.1:9151"}
	var activeEndpoint string

	for _, ep := range endpoints {
		conn, err := net.DialTimeout("tcp", ep, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			activeEndpoint = ep
			break
		}
	}

	if activeEndpoint == "" {
		t.Log("[LIVE TOR STATUS: UNVERIFIED] No local Tor daemon active on 127.0.0.1:9051 or 127.0.0.1:9151. Live integration remains UNVERIFIED on this host.")
		t.Skip("Live Tor daemon not detected on 127.0.0.1:9051 or 127.0.0.1:9151. Live integration test marked UNVERIFIED and skipped.")
		return
	}

	t.Logf("Detected live Tor daemon at %s; executing live SAFECOOKIE and control queries", activeEndpoint)

	cfg := config.DefaultConfig()
	cfg.Tor.Enabled = true
	cfg.Tor.ControlEndpoint = activeEndpoint
	cfg.Tor.ConnectionTimeout = 3 * time.Second

	client := NewClient(cfg, nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authResult, err := client.ConnectAndAuthenticate(ctx)
	if err != nil {
		t.Fatalf("Live Tor daemon authentication failed at %s: %v", activeEndpoint, err)
	}

	if !authResult.Success {
		t.Fatalf("Live Tor daemon authentication rejected: %s", authResult.Error)
	}

	ver, err := client.GetVersion(ctx)
	if err != nil {
		t.Errorf("failed to get live Tor version: %v", err)
	} else {
		t.Logf("Live Tor Version: %s", ver)
	}

	boot, err := client.GetBootstrapStatus(ctx)
	if err != nil {
		t.Errorf("failed to get live Tor bootstrap status: %v", err)
	} else {
		t.Logf("Live Tor Bootstrap: %d%% (tag: %s, summary: %s)", boot.Progress, boot.Tag, boot.Summary)
	}

	circuits, err := client.GetActiveCircuits(ctx)
	if err != nil {
		t.Errorf("failed to get live Tor circuits: %v", err)
	} else {
		t.Logf("Live Tor Active Circuits: %d", len(circuits))
	}
}
