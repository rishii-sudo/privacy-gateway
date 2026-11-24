package privacy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/config"
	"github.com/rishii-sudo/privacy-gateway/internal/tor"
)

func TestCheckerBaselineRuns(t *testing.T) {
	cfg := config.DefaultConfig()
	checker := NewChecker(cfg)

	results, err := checker.RunAllBaselineChecks()
	if err != nil {
		t.Fatalf("RunAllBaselineChecks failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("expected non-empty results from baseline checks")
	}

	// Verify each result has valid status and UTC timestamp
	foundNotImplemented := false
	for _, r := range results {
		if !r.Status.IsValid() {
			t.Errorf("result %s has invalid status %s", r.ID, r.Status)
		}
		if r.Timestamp.IsZero() {
			t.Errorf("result %s has zero timestamp", r.ID)
		}
		if r.Status == StatusNotImplemented {
			foundNotImplemented = true
		}
	}

	if !foundNotImplemented {
		t.Errorf("expected stubbed checks with StatusNotImplemented for future milestones")
	}
}

func TestCheckDNSResolverPrivacy(t *testing.T) {
	// Important correction 1: A private DNS resolver does not prove plaintext ISP DNS -> INCONCLUSIVE
	cfg := config.DefaultConfig()
	cfg.Network.DnsServers = []string{"192.168.1.1"}
	checker := NewChecker(cfg)

	res := checker.CheckDNSResolverPrivacy()
	if res.Status != StatusInconclusive {
		t.Errorf("expected INCONCLUSIVE for private resolver without active query inspection, got %s", res.Status)
	}

	// Important correction 2: A public DNS resolver does not prove encrypted DNS -> INCONCLUSIVE
	cfg.Network.DnsServers = []string{"1.1.1.1", "9.9.9.9"}
	checker = NewChecker(cfg)
	res = checker.CheckDNSResolverPrivacy()
	if res.Status != StatusInconclusive {
		t.Errorf("expected INCONCLUSIVE for public resolver without encrypted transport verification, got %s", res.Status)
	}
}

func TestCheckHostnameExposure(t *testing.T) {
	checker := NewChecker(nil)
	res := checker.CheckHostnameExposure()
	if !res.Status.IsValid() {
		t.Errorf("unexpected invalid status from CheckHostnameExposure: %s", res.Status)
	}
	// Conservative check: Identifying vendor/device name -> INCONCLUSIVE; generic -> PASS
	if res.Status != StatusPass && res.Status != StatusInconclusive {
		t.Errorf("expected PASS or INCONCLUSIVE for hostname check, got %s", res.Status)
	}

	// Privacy Requirement: current_user must NEVER be collected or present in details
	if _, exists := res.Details["current_user"]; exists {
		t.Errorf("CheckHostnameExposure details must not contain 'current_user'")
	}
	if host, ok := res.Details["hostname"]; !ok || host == "" {
		t.Errorf("CheckHostnameExposure details must retain 'hostname'")
	}
	for k := range res.Details {
		if k != "hostname" {
			t.Errorf("CheckHostnameExposure recorded unnecessary detail %q; only 'hostname' is permitted", k)
		}
	}
}

func TestCheckIPv6Exposure(t *testing.T) {
	checker := NewChecker(nil)
	res := checker.CheckIPv6Exposure()
	if !res.Status.IsValid() {
		t.Errorf("unexpected invalid status from CheckIPv6Exposure: %s", res.Status)
	}
	// Important correction: A global IPv6 address does not automatically establish a leak -> Must be PASS (none) or INCONCLUSIVE (present)
	if res.Status != StatusPass && res.Status != StatusInconclusive {
		t.Errorf("expected PASS or INCONCLUSIVE for IPv6 exposure check, got %s", res.Status)
	}
}

func TestCheckInterfaceExposure(t *testing.T) {
	checker := NewChecker(nil)
	res := checker.CheckInterfaceExposure()
	if !res.Status.IsValid() {
		t.Errorf("unexpected invalid status from CheckInterfaceExposure: %s", res.Status)
	}
	// Must be PASS (no physical interfaces), FAIL (physical with no VPN), or INCONCLUSIVE (VPN present or unknown adapter)
	if res.Status != StatusPass && res.Status != StatusFail && res.Status != StatusInconclusive {
		t.Errorf("unexpected status for interface exposure: %s", res.Status)
	}

	// Verify remediation text does NOT falsely claim launching Tor automatically shields all system traffic
	if res.Remediation != "" {
		if strings.Contains(res.Remediation, "launch Tor to shield physical interface traffic") {
			t.Errorf("remediation must not claim Tor automatically shields all system traffic")
		}
		if res.Status == StatusFail {
			if !strings.Contains(res.Remediation, "system-wide VPN") && !strings.Contains(res.Remediation, "routing policy") {
				t.Errorf("remediation must explain verified system-wide VPN route or enforced routing policy is required")
			}
		}
	}
}

func TestCheckTorDisabledReturnsInconclusive(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tor.Enabled = false
	checker := NewChecker(cfg)

	resAuth := checker.CheckTorAuth()
	if resAuth.Status != StatusInconclusive {
		t.Errorf("expected INCONCLUSIVE for disabled Tor auth check, got %s", resAuth.Status)
	}

	resBoot := checker.CheckTorBootstrap()
	if resBoot.Status != StatusInconclusive {
		t.Errorf("expected INCONCLUSIVE for disabled Tor bootstrap check, got %s", resBoot.Status)
	}

	resCirc := checker.CheckTorCircuitStatus()
	if resCirc.Status != StatusInconclusive {
		t.Errorf("expected INCONCLUSIVE for disabled Tor circuit check, got %s", resCirc.Status)
	}
}

func TestCheckTorAllPassWithCautions(t *testing.T) {
	server, _, err := tor.NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock tor server: %v", err)
	}
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Tor.Enabled = true
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second

	client := server.Client(cfg, nil)
	defer client.Close()

	checker := NewChecker(cfg)
	checker.SetTorClient(client)

	// 1. Auth check
	resAuth := checker.CheckTorAuth()
	if resAuth.Status != StatusPass {
		t.Errorf("expected PASS for Tor auth check, got %s: %s", resAuth.Status, resAuth.Summary)
	}
	cautionAuth, _ := resAuth.Details["caution"].(string)
	if !strings.Contains(cautionAuth, "does NOT imply that system traffic is routed through Tor") {
		t.Errorf("expected caution warning on auth check, got: %s", cautionAuth)
	}

	// 2. Bootstrap check
	resBoot := checker.CheckTorBootstrap()
	if resBoot.Status != StatusPass {
		t.Errorf("expected PASS for Tor bootstrap check, got %s: %s", resBoot.Status, resBoot.Summary)
	}
	cautionBoot, _ := resBoot.Details["caution"].(string)
	if !strings.Contains(cautionBoot, "explicit SOCKS5 proxy configuration") {
		t.Errorf("expected caution warning on bootstrap check, got: %s", cautionBoot)
	}

	// 3. Circuit check
	resCirc := checker.CheckTorCircuitStatus()
	if resCirc.Status != StatusPass {
		t.Errorf("expected PASS for Tor circuit check, got %s: %s", resCirc.Status, resCirc.Summary)
	}
	cautionCirc, _ := resCirc.Details["caution"].(string)
	if !strings.Contains(cautionCirc, "Host traffic is not automatically protected") {
		t.Errorf("expected caution warning on circuit check, got: %s", cautionCirc)
	}
}

func TestCheckTorSemanticIndependenceMatrix(t *testing.T) {
	// Matrix of semantic independence:
	// 1. Endpoint Unreachable -> Auth: INCONCLUSIVE, Bootstrap: INCONCLUSIVE, Circuit: INCONCLUSIVE
	t.Run("UnreachableEndpoint", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Tor.Enabled = true
		cfg.Tor.ControlEndpoint = "127.0.0.1:59998" // unreachable port
		cfg.Tor.ConnectionTimeout = 100 * time.Millisecond

		checker := NewChecker(cfg)

		resAuth := checker.CheckTorAuth()
		if resAuth.Status != StatusInconclusive {
			t.Errorf("expected INCONCLUSIVE for auth on unreachable endpoint, got %s", resAuth.Status)
		}
		resBoot := checker.CheckTorBootstrap()
		if resBoot.Status != StatusInconclusive {
			t.Errorf("expected INCONCLUSIVE for bootstrap on unreachable endpoint, got %s", resBoot.Status)
		}
		resCirc := checker.CheckTorCircuitStatus()
		if resCirc.Status != StatusInconclusive {
			t.Errorf("expected INCONCLUSIVE for circuits on unreachable endpoint, got %s", resCirc.Status)
		}
	})

	// 2. Auth Fails Closed -> Auth: FAIL, Bootstrap: INCONCLUSIVE, Circuit: INCONCLUSIVE
	t.Run("AuthFailsClosed", func(t *testing.T) {
		server, _, err := tor.NewInMemoryMockTorServer()
		if err != nil {
			t.Fatalf("failed to create mock server: %v", err)
		}
		defer server.Close()
		server.SetRejectAuth(true)

		cfg := config.DefaultConfig()
		cfg.Tor.Enabled = true
		cfg.Tor.ControlEndpoint = server.Addr()
		cfg.Tor.CookiePath = server.CookiePath()
		cfg.Tor.ConnectionTimeout = 2 * time.Second

		client := server.Client(cfg, nil)
		defer client.Close()

		checker := NewChecker(cfg)
		checker.SetTorClient(client)

		resAuth := checker.CheckTorAuth()
		if resAuth.Status != StatusFail {
			t.Errorf("expected FAIL for rejected auth, got %s", resAuth.Status)
		}
		resBoot := checker.CheckTorBootstrap()
		if resBoot.Status != StatusInconclusive {
			t.Errorf("expected INCONCLUSIVE for bootstrap when auth failed, got %s", resBoot.Status)
		}
		resCirc := checker.CheckTorCircuitStatus()
		if resCirc.Status != StatusInconclusive {
			t.Errorf("expected INCONCLUSIVE for circuits when auth failed, got %s", resCirc.Status)
		}
	})

	// 3. Auth PASS, Bootstrap Incomplete (35%), Circuit Inconclusive (0 built)
	t.Run("AuthPass_BootstrapIncomplete_CircuitNotBuilt", func(t *testing.T) {
		server, _, err := tor.NewInMemoryMockTorServer()
		if err != nil {
			t.Fatalf("failed to create mock server: %v", err)
		}
		defer server.Close()
		server.SetBootstrapStatus(35, "conn_dir", "Connecting to directory server")
		server.SetCircuits("", false)

		cfg := config.DefaultConfig()
		cfg.Tor.Enabled = true
		cfg.Tor.ControlEndpoint = server.Addr()
		cfg.Tor.CookiePath = server.CookiePath()
		cfg.Tor.ConnectionTimeout = 2 * time.Second

		client := server.Client(cfg, nil)
		defer client.Close()

		checker := NewChecker(cfg)
		checker.SetTorClient(client)

		resAuth := checker.CheckTorAuth()
		if resAuth.Status != StatusPass {
			t.Errorf("expected PASS for auth, got %s", resAuth.Status)
		}
		resBoot := checker.CheckTorBootstrap()
		if resBoot.Status != StatusInconclusive {
			t.Errorf("expected INCONCLUSIVE for bootstrap at 35%%, got %s", resBoot.Status)
		}
		resCirc := checker.CheckTorCircuitStatus()
		if resCirc.Status != StatusInconclusive {
			t.Errorf("expected INCONCLUSIVE for circuits when none built, got %s", resCirc.Status)
		}
	})

	// 4. Auth PASS, Bootstrap Complete (100%), Circuit Inconclusive (0 built)
	t.Run("AuthPass_BootstrapComplete_CircuitNotBuilt", func(t *testing.T) {
		server, _, err := tor.NewInMemoryMockTorServer()
		if err != nil {
			t.Fatalf("failed to create mock server: %v", err)
		}
		defer server.Close()
		server.SetBootstrapStatus(100, "done", "Done")
		server.SetCircuits("", false)

		cfg := config.DefaultConfig()
		cfg.Tor.Enabled = true
		cfg.Tor.ControlEndpoint = server.Addr()
		cfg.Tor.CookiePath = server.CookiePath()
		cfg.Tor.ConnectionTimeout = 2 * time.Second

		client := server.Client(cfg, nil)
		defer client.Close()

		checker := NewChecker(cfg)
		checker.SetTorClient(client)

		resAuth := checker.CheckTorAuth()
		if resAuth.Status != StatusPass {
			t.Errorf("expected PASS for auth, got %s", resAuth.Status)
		}
		resBoot := checker.CheckTorBootstrap()
		if resBoot.Status != StatusPass {
			t.Errorf("expected PASS for bootstrap at 100%%, got %s", resBoot.Status)
		}
		resCirc := checker.CheckTorCircuitStatus()
		if resCirc.Status != StatusInconclusive {
			t.Errorf("expected INCONCLUSIVE for circuits when none built, got %s", resCirc.Status)
		}
	})

	// 5. Auth PASS, Bootstrap Complete (100%), Circuits PASS (1 BUILT)
	t.Run("AuthPass_BootstrapComplete_CircuitsBuilt", func(t *testing.T) {
		server, _, err := tor.NewInMemoryMockTorServer()
		if err != nil {
			t.Fatalf("failed to create mock server: %v", err)
		}
		defer server.Close()
		server.SetBootstrapStatus(100, "done", "Done")
		server.SetCircuits("1 BUILT $1111111111111111111111111111111111111111~Guard PURPOSE=GENERAL", true)

		cfg := config.DefaultConfig()
		cfg.Tor.Enabled = true
		cfg.Tor.ControlEndpoint = server.Addr()
		cfg.Tor.CookiePath = server.CookiePath()
		cfg.Tor.ConnectionTimeout = 2 * time.Second

		client := server.Client(cfg, nil)
		defer client.Close()

		checker := NewChecker(cfg)
		checker.SetTorClient(client)

		resAuth := checker.CheckTorAuth()
		if resAuth.Status != StatusPass {
			t.Errorf("expected PASS for auth, got %s", resAuth.Status)
		}
		resBoot := checker.CheckTorBootstrap()
		if resBoot.Status != StatusPass {
			t.Errorf("expected PASS for bootstrap, got %s", resBoot.Status)
		}
		resCirc := checker.CheckTorCircuitStatus()
		if resCirc.Status != StatusPass {
			t.Errorf("expected PASS for circuits, got %s", resCirc.Status)
		}

		// Verify cautions
		if caution, ok := resAuth.Details["caution"].(string); !ok || !strings.Contains(caution, "does NOT imply that system traffic is routed") {
			t.Errorf("auth check missing traffic routing caution")
		}
		if caution, ok := resBoot.Details["caution"].(string); !ok || !strings.Contains(caution, "explicit SOCKS5 proxy configuration") {
			t.Errorf("bootstrap check missing SOCKS5 proxy caution")
		}
		if caution, ok := resCirc.Details["caution"].(string); !ok || !strings.Contains(caution, "Host traffic is not automatically protected") {
			t.Errorf("circuit check missing host traffic caution")
		}
	})
}

func TestCheckTorAuthFailClosed(t *testing.T) {
	server, _, err := tor.NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock tor server: %v", err)
	}
	defer server.Close()

	// Simulate server rejecting authentication
	server.SetRejectAuth(true)

	cfg := config.DefaultConfig()
	cfg.Tor.Enabled = true
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second

	client := server.Client(cfg, nil)
	defer client.Close()

	checker := NewChecker(cfg)
	checker.SetTorClient(client)

	// Auth must FAIL closed
	resAuth := checker.CheckTorAuth()
	if resAuth.Status != StatusFail {
		t.Errorf("expected FAIL for rejected authentication, got %s", resAuth.Status)
	}

	// Bootstrap must be INCONCLUSIVE (fails safe, does not guess)
	resBoot := checker.CheckTorBootstrap()
	if resBoot.Status != StatusInconclusive {
		t.Errorf("expected INCONCLUSIVE for bootstrap when unauthenticated, got %s", resBoot.Status)
	}

	// Circuit must be INCONCLUSIVE (fails safe, does not guess)
	resCirc := checker.CheckTorCircuitStatus()
	if resCirc.Status != StatusInconclusive {
		t.Errorf("expected INCONCLUSIVE for circuit when unauthenticated, got %s", resCirc.Status)
	}
}

func TestCheckTorCircuitStatusDegradedOnQueueOverflow(t *testing.T) {
	server, _, err := tor.NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock tor server: %v", err)
	}
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Tor.Enabled = true
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second
	cfg.Tor.EventQueueLimit = 20

	client := server.Client(cfg, nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.ConnectAndAuthenticate(ctx); err != nil {
		t.Fatalf("failed to connect and authenticate: %v", err)
	}

	// Subscribe to events and saturate buffer
	_, err = client.SubscribeEvents(ctx, "STATUS_CLIENT")
	if err != nil {
		t.Fatalf("failed to subscribe to events: %v", err)
	}

	// Flood events to force buffer overflow
	for i := 0; i < 50; i++ {
		server.BroadcastAsyncEvent("650 STATUS_CLIENT NOTICE OVERFLOW")
	}

	// Allow reader loop to process and trigger drop
	time.Sleep(50 * time.Millisecond)

	if !client.IsMonitoringDegraded() {
		t.Fatalf("expected client monitoring to be degraded after flood")
	}

	checker := NewChecker(cfg)
	checker.SetTorClient(client)

	// Circuit check must return INCONCLUSIVE due to degraded monitoring
	resCirc := checker.CheckTorCircuitStatus()
	if resCirc.Status != StatusInconclusive {
		t.Errorf("expected INCONCLUSIVE for circuit check on degraded monitoring, got %s", resCirc.Status)
	}
	if !strings.Contains(resCirc.Summary, "degraded") {
		t.Errorf("expected summary to mention degraded monitoring, got: %s", resCirc.Summary)
	}
	if resCirc.Details["monitoring_health"] != string(tor.MonitoringHealthDegraded) {
		t.Errorf("expected monitoring_health DEGRADED in details, got: %v", resCirc.Details["monitoring_health"])
	}
}

func TestCheckTorAuthRequiresValidSafeCookie(t *testing.T) {
	// Scenario 1: Authentication failure (server rejects authentication)
	t.Run("RejectedAuthentication", func(t *testing.T) {
		server, _, err := tor.NewInMemoryMockTorServer()
		if err != nil {
			t.Fatalf("failed to create mock tor server: %v", err)
		}
		defer server.Close()
		server.SetRejectAuth(true)

		cfg := config.DefaultConfig()
		cfg.Tor.Enabled = true
		cfg.Tor.ControlEndpoint = server.Addr()
		cfg.Tor.CookiePath = server.CookiePath()
		cfg.Tor.ConnectionTimeout = 2 * time.Second

		client := server.Client(cfg, nil)
		defer client.Close()

		checker := NewChecker(cfg)
		checker.SetTorClient(client)

		res := checker.CheckTorAuth()
		if res.Status != StatusFail {
			t.Errorf("expected StatusFail for rejected auth, got %s", res.Status)
		}
		if !strings.Contains(res.Summary, "authentication failed closed") && !strings.Contains(res.Summary, "authentication verification failed") {
			t.Errorf("expected summary to note auth failure, got: %s", res.Summary)
		}
	})

	// Scenario 2: Protocol downgrade attempt (daemon only advertises HASHEDPASSWORD)
	t.Run("ProhibitedDowngradeHashedPassword", func(t *testing.T) {
		server, _, err := tor.NewInMemoryMockTorServer()
		if err != nil {
			t.Fatalf("failed to create mock tor server: %v", err)
		}
		defer server.Close()
		server.SetAuthMethods("HASHEDPASSWORD")

		cfg := config.DefaultConfig()
		cfg.Tor.Enabled = true
		cfg.Tor.ControlEndpoint = server.Addr()
		cfg.Tor.CookiePath = server.CookiePath()
		cfg.Tor.ConnectionTimeout = 2 * time.Second

		client := server.Client(cfg, nil)
		defer client.Close()

		checker := NewChecker(cfg)
		checker.SetTorClient(client)

		res := checker.CheckTorAuth()
		if res.Status != StatusFail {
			t.Errorf("expected StatusFail when SAFECOOKIE is missing, got %s", res.Status)
		}
	})

	// Scenario 3: Corrupt HMAC / Server Hash verification failure
	t.Run("CorruptServerHMAC", func(t *testing.T) {
		server, _, err := tor.NewInMemoryMockTorServer()
		if err != nil {
			t.Fatalf("failed to create mock tor server: %v", err)
		}
		defer server.Close()
		server.SetCorruptServerHash(true)

		cfg := config.DefaultConfig()
		cfg.Tor.Enabled = true
		cfg.Tor.ControlEndpoint = server.Addr()
		cfg.Tor.CookiePath = server.CookiePath()
		cfg.Tor.ConnectionTimeout = 2 * time.Second

		client := server.Client(cfg, nil)
		defer client.Close()

		checker := NewChecker(cfg)
		checker.SetTorClient(client)

		res := checker.CheckTorAuth()
		if res.Status != StatusFail {
			t.Errorf("expected StatusFail when server HMAC is corrupted, got %s", res.Status)
		}
		if !strings.Contains(res.Summary, "authentication failed closed") {
			t.Errorf("expected summary to state auth failed closed, got: %s", res.Summary)
		}
	})

	// Scenario 4: Protocol downgrade attempt (daemon only advertises NULL)
	t.Run("ProhibitedDowngradeNull", func(t *testing.T) {
		server, _, err := tor.NewInMemoryMockTorServer()
		if err != nil {
			t.Fatalf("failed to create mock tor server: %v", err)
		}
		defer server.Close()
		server.SetAuthMethods("NULL")

		cfg := config.DefaultConfig()
		cfg.Tor.Enabled = true
		cfg.Tor.ControlEndpoint = server.Addr()
		cfg.Tor.CookiePath = server.CookiePath()
		cfg.Tor.ConnectionTimeout = 2 * time.Second

		client := server.Client(cfg, nil)
		defer client.Close()

		checker := NewChecker(cfg)
		checker.SetTorClient(client)

		res := checker.CheckTorAuth()
		if res.Status != StatusFail {
			t.Errorf("expected StatusFail when daemon advertises NULL, got %s", res.Status)
		}
	})
}

func TestCheckTorAuthHandlesGetVersionFailure(t *testing.T) {
	server, _, err := tor.NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock tor server: %v", err)
	}
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Tor.Enabled = true
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second

	client := server.Client(cfg, nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := client.ConnectAndAuthenticate(ctx); err != nil {
		t.Fatalf("failed to connect and authenticate: %v", err)
	}

	// Hang commands to force GetVersion to time out / fail
	server.SetHangCommands(true)

	checker := NewChecker(cfg)
	checker.SetTorClient(client)

	res := checker.CheckTorAuth()
	if res.Status != StatusPass {
		t.Errorf("expected auth StatusPass even if version query fails, got: %s", res.Status)
	}
	if !strings.Contains(res.Summary, "version query failed") {
		t.Errorf("expected summary to explicitly state version query failed, got: %s", res.Summary)
	}
	if res.Details["version"] != nil {
		t.Errorf("expected details[version] to be nil on failure, got: %v", res.Details["version"])
	}
	if res.Details["version_error"] == nil {
		t.Errorf("expected details[version_error] to be populated")
	}
}
