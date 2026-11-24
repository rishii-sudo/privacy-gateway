package tor

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/config"
	"github.com/rishii-sudo/privacy-gateway/internal/logging"
)

func TestUnimplementedController(t *testing.T) {
	c := &UnimplementedController{}
	if err := c.Connect("127.0.0.1:9051", ""); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := c.GetBootstrapStatus(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := c.GetActiveCircuits(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if err := c.RequestNewIdentity(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("expected nil error on Close, got %v", err)
	}
}

func TestSafeCookieHandshakeSuccess(t *testing.T) {
	server, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second

	logger, _ := logging.New(logging.Options{LogToConsole: false, LogToFile: false})
	client := server.Client(cfg, logger)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	authResult, err := client.ConnectAndAuthenticate(ctx)
	if err != nil {
		t.Fatalf("ConnectAndAuthenticate failed: %v", err)
	}

	if !authResult.Success {
		t.Errorf("expected auth success, got failure: %s", authResult.Error)
	}
	if authResult.Method != "SAFECOOKIE" {
		t.Errorf("expected method SAFECOOKIE, got %s", authResult.Method)
	}
	if client.State() != StateAuthenticated {
		t.Errorf("expected state StateAuthenticated, got %s", client.State())
	}
}

func TestSafeCookieHMACMismatchFailsClosed(t *testing.T) {
	server, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	// Corrupt server HMAC
	server.SetCorruptServerHash(true)

	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second

	logger, _ := logging.New(logging.Options{LogToConsole: false, LogToFile: false})
	client := server.Client(cfg, logger)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = client.ConnectAndAuthenticate(ctx)
	if err == nil {
		t.Fatalf("expected error on corrupt server HMAC, got nil")
	}

	if !errors.Is(err, ErrInvalidHMAC) {
		t.Errorf("expected ErrInvalidHMAC, got: %v", err)
	}

	if client.State() == StateAuthenticated {
		t.Errorf("client must not be authenticated on HMAC mismatch")
	}
}

func TestSafeCookieAuthenticationRejectedByServer(t *testing.T) {
	server, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	server.SetRejectAuth(true)

	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second

	logger, _ := logging.New(logging.Options{LogToConsole: false, LogToFile: false})
	client := server.Client(cfg, logger)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = client.ConnectAndAuthenticate(ctx)
	if err == nil {
		t.Fatalf("expected error when server rejects authenticate, got nil")
	}

	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed, got: %v", err)
	}
}

func TestCookieFileSizeValidation(t *testing.T) {
	tempDir := t.TempDir()

	// Test empty path
	if _, err := ValidateAndReadCookieFile(""); err == nil {
		t.Errorf("expected error on empty cookie path")
	}

	// Test 31 bytes
	path31 := filepath.Join(tempDir, "cookie31")
	if err := os.WriteFile(path31, make([]byte, 31), 0600); err != nil {
		t.Fatalf("failed to write path31: %v", err)
	}
	if _, err := ValidateAndReadCookieFile(path31); !errors.Is(err, ErrInvalidCookieSize) {
		t.Errorf("expected ErrInvalidCookieSize for 31 bytes, got: %v", err)
	}

	// Test 33 bytes
	path33 := filepath.Join(tempDir, "cookie33")
	if err := os.WriteFile(path33, make([]byte, 33), 0600); err != nil {
		t.Fatalf("failed to write path33: %v", err)
	}
	if _, err := ValidateAndReadCookieFile(path33); !errors.Is(err, ErrInvalidCookieSize) {
		t.Errorf("expected ErrInvalidCookieSize for 33 bytes, got: %v", err)
	}

	// Test exact 32 bytes
	path32 := filepath.Join(tempDir, "cookie32")
	expected := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(path32, expected, 0600); err != nil {
		t.Fatalf("failed to write path32: %v", err)
	}
	data, err := ValidateAndReadCookieFile(path32)
	if err != nil {
		t.Fatalf("failed to read valid 32-byte cookie: %v", err)
	}
	if string(data) != string(expected) {
		t.Errorf("read cookie data mismatch")
	}
}

func TestCommandsExecution(t *testing.T) {
	server, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second

	logger, _ := logging.New(logging.Options{LogToConsole: false, LogToFile: false})
	client := server.Client(cfg, logger)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.ConnectAndAuthenticate(ctx); err != nil {
		t.Fatalf("failed to connect and authenticate: %v", err)
	}

	// 1. GetVersion
	ver, err := client.GetVersion(ctx)
	if err != nil {
		t.Errorf("GetVersion failed: %v", err)
	}
	if ver != "0.4.8.10" {
		t.Errorf("expected version 0.4.8.10, got %q", ver)
	}

	// 2. GetBootstrapStatus
	boot, err := client.GetBootstrapStatus(ctx)
	if err != nil {
		t.Errorf("GetBootstrapStatus failed: %v", err)
	}
	if boot.Progress != 100 {
		t.Errorf("expected bootstrap progress 100, got %d", boot.Progress)
	}
	if boot.Tag != "done" {
		t.Errorf("expected bootstrap tag 'done', got %q", boot.Tag)
	}
	if !boot.Ready {
		t.Errorf("expected bootstrap ready=true")
	}

	// 3. GetCircuitEstablished
	est, err := client.GetCircuitEstablished(ctx)
	if err != nil {
		t.Errorf("GetCircuitEstablished failed: %v", err)
	}
	if !est {
		t.Errorf("expected circuit established true")
	}

	// 4. GetActiveCircuits
	circuits, err := client.GetActiveCircuits(ctx)
	if err != nil {
		t.Errorf("GetActiveCircuits failed: %v", err)
	}
	if len(circuits) == 0 {
		t.Errorf("expected at least 1 circuit, got 0")
	} else {
		c := circuits[0]
		if c.ID != "1" {
			t.Errorf("expected circuit ID 1, got %q", c.ID)
		}
		if c.Status != "BUILT" {
			t.Errorf("expected status BUILT, got %q", c.Status)
		}
		if len(c.Path) != 2 {
			t.Errorf("expected 2 hops in path, got %d", len(c.Path))
		}
	}

	// 5. GetSocksListeners
	socks, err := client.GetSocksListeners(ctx)
	if err != nil {
		t.Errorf("GetSocksListeners failed: %v", err)
	}
	if len(socks) == 0 || socks[0] != "127.0.0.1:9050" {
		t.Errorf("expected socks listener 127.0.0.1:9050, got %v", socks)
	}
}

func TestSignalNewnymDisabledInM2(t *testing.T) {
	cfg := config.DefaultConfig()
	client := NewClient(cfg, nil)

	err := client.RequestNewIdentity()
	if !errors.Is(err, ErrSignalNewnymDisabled) {
		t.Errorf("expected ErrSignalNewnymDisabled, got: %v", err)
	}
}

func TestEventStreamingAndQueueDrop(t *testing.T) {
	server, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second
	cfg.Tor.EventQueueLimit = 50 // smaller buffer for testing queue saturation

	logger, _ := logging.New(logging.Options{LogToConsole: false, LogToFile: false})
	client := server.Client(cfg, logger)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.ConnectAndAuthenticate(ctx); err != nil {
		t.Fatalf("ConnectAndAuthenticate failed: %v", err)
	}

	eventCh, err := client.SubscribeEvents(ctx, "STATUS_CLIENT")
	if err != nil {
		t.Fatalf("SubscribeEvents failed: %v", err)
	}

	// Send an event from mock server
	testEventLine := "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=90 TAG=conn_done SUMMARY=\"Connected to the Tor network\""
	server.BroadcastAsyncEvent(testEventLine)

	select {
	case evt := <-eventCh:
		if evt.Type != "STATUS_CLIENT" {
			t.Errorf("expected event type STATUS_CLIENT, got %q", evt.Type)
		}
		if evt.Severity != "NOTICE" {
			t.Errorf("expected severity NOTICE, got %q", evt.Severity)
		}
		if evt.Details["PROGRESS"] != "90" {
			t.Errorf("expected PROGRESS=90, got %q", evt.Details["PROGRESS"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for async event")
	}

	// Blast 150 events to verify queue drop handling does not deadlock or crash
	for i := 0; i < 150; i++ {
		server.BroadcastAsyncEvent("650 STATUS_CLIENT NOTICE FLOOD")
	}

	// Client and event channel remain responsive
	drainCount := 0
drainLoop:
	for {
		select {
		case <-eventCh:
			drainCount++
		case <-time.After(50 * time.Millisecond):
			break drainLoop
		}
	}
	if drainCount == 0 {
		t.Errorf("expected to drain some buffered events, got 0")
	}

	// Gap 1: Verify event queue overflow produces an explicit DEGRADED monitoring state
	if !client.IsMonitoringDegraded() {
		t.Errorf("expected client monitoring state to be degraded after queue overflow")
	}
	mon := client.MonitoringStatus()
	if mon.Health != MonitoringHealthDegraded {
		t.Errorf("expected MonitoringHealthDegraded, got %s", mon.Health)
	}
	if mon.DroppedEvents == 0 {
		t.Errorf("expected dropped events count > 0, got %d", mon.DroppedEvents)
	}
}

func TestCommandTimeoutHandling(t *testing.T) {
	server, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	server.SetHangCommands(true)

	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 100 * time.Millisecond // very short timeout for test

	logger, _ := logging.New(logging.Options{LogToConsole: false, LogToFile: false})
	client := server.Client(cfg, logger)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.ConnectAndAuthenticate(ctx); err != nil {
		t.Fatalf("ConnectAndAuthenticate failed: %v", err)
	}

	_, err = client.GetVersion(ctx)
	if err == nil {
		t.Fatalf("expected command timeout error, got nil")
	}
	if !errors.Is(err, ErrCommandTimeout) && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected ErrCommandTimeout or DeadlineExceeded, got %v", err)
	}
}

func TestDisconnectAndClosedState(t *testing.T) {
	server, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 2 * time.Second

	logger, _ := logging.New(logging.Options{LogToConsole: false, LogToFile: false})
	client := server.Client(cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.ConnectAndAuthenticate(ctx); err != nil {
		t.Fatalf("ConnectAndAuthenticate failed: %v", err)
	}

	// Close client
	if err := client.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	if client.State() != StateClosed {
		t.Errorf("expected state StateClosed, got %s", client.State())
	}

	// Subsequent command should fail with ErrInvalidState or ErrNotConnected
	_, err = client.GetVersion(ctx)
	if err == nil {
		t.Errorf("expected error after close, got nil")
	}
}

func TestInspectorBridgeFallback(t *testing.T) {
	// Point to a non-existent inspector path to verify Go fallback parsing works seamlessly
	bridge := NewInspectorBridge("non_existent_binary_xyz", 200*time.Millisecond)

	rawBootstrap := "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=85 TAG=handshake_dir SUMMARY=\"Handshaking with directory server\"\n250 OK"
	status, err := bridge.ParseBootstrap(rawBootstrap)
	if err != nil {
		t.Fatalf("expected fallback bootstrap parse to succeed: %v", err)
	}
	if status.Progress != 85 {
		t.Errorf("expected progress 85, got %d", status.Progress)
	}
	if status.Tag != "handshake_dir" {
		t.Errorf("expected tag handshake_dir, got %q", status.Tag)
	}

	rawCircuits := "250-circuit-status=10 BUILT $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~Node1,$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB~Node2 BUILD_FLAGS=IS_INTERNAL PURPOSE=GENERAL\n250 OK"
	circuits, err := bridge.ParseCircuits(rawCircuits)
	if err != nil {
		t.Fatalf("expected fallback circuits parse to succeed: %v", err)
	}
	if len(circuits) != 1 {
		t.Fatalf("expected 1 circuit, got %d", len(circuits))
	}
	if circuits[0].ID != "10" {
		t.Errorf("expected circuit ID 10, got %q", circuits[0].ID)
	}
	if len(circuits[0].Path) != 2 {
		t.Errorf("expected 2 hops in path, got %d", len(circuits[0].Path))
	}
}

func TestLoopbackEndpointSecurityEnforcement(t *testing.T) {
	cases := []struct {
		name        string
		endpoint    string
		expectError bool
		errorSubstr string
	}{
		{"remote ipv4", "192.168.1.100:9051", true, "security violation: remote tor endpoint"},
		{"remote public ip", "8.8.8.8:9051", true, "security violation: remote tor endpoint"},
		{"remote domain unresolvable", "tor.example.com:9051", true, "failed to resolve tor host"},
		{"malformed no port", "127.0.0.1", true, "invalid tor.control_endpoint"},
		{"malformed text", "invalid_endpoint", true, "invalid tor.control_endpoint"},
		{"port zero", "127.0.0.1:0", true, "port must be a number between 1 and 65535"},
		{"port out of bounds high", "127.0.0.1:65536", true, "port must be a number between 1 and 65535"},
		{"port negative", "127.0.0.1:-1", true, "port must be a number between 1 and 65535"},
		{"port non-numeric", "127.0.0.1:abc", true, "port must be a number between 1 and 65535"},
		{"valid standard loopback", "127.0.0.1:9051", false, ""},
		{"valid ipv4 loopback range", "127.0.0.5:9151", false, ""},
		{"valid ipv6 loopback", "[::1]:9051", false, ""},
		{"valid localhost", "localhost:9051", false, ""},
		{"valid port boundary min", "127.0.0.1:1", false, ""},
		{"valid port boundary max", "127.0.0.1:65535", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Tor.ControlEndpoint = tc.endpoint

			client := NewClient(cfg, nil)
			// Mock dialer so we only test endpoint validation in Connect, not actual network reachability
			client.setDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("dial intercepted for testing")
			})

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()

			err := client.Connect(ctx)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error for endpoint %q, got nil", tc.endpoint)
				}
				if !strings.Contains(err.Error(), tc.errorSubstr) {
					t.Errorf("expected error containing %q, got: %v", tc.errorSubstr, err)
				}
			} else {
				// We expect error to be our dial intercept error, NOT a security or validation violation
				if err != nil && (strings.Contains(err.Error(), "security violation") || strings.Contains(err.Error(), "invalid tor.control_endpoint")) {
					t.Errorf("unexpected security/validation error for valid loopback %q: %v", tc.endpoint, err)
				}
			}
		})
	}
}

func TestValidateDestinationAddress_ProductionFunction(t *testing.T) {
	cases := []struct {
		name        string
		network     string
		address     string
		expectError bool
		errorSubstr string
	}{
		{"ipv4 standard loopback", "tcp", "127.0.0.1:9051", false, ""},
		{"ipv4 extended loopback", "tcp", "127.0.0.2:9151", false, ""},
		{"ipv4 boundary loopback", "tcp", "127.255.255.255:9051", false, ""},
		{"ipv6 loopback", "tcp", "[::1]:9051", false, ""},
		{"private lan 192.168", "tcp", "192.168.1.1:9051", true, "security violation: raw connection attempted to non-loopback destination"},
		{"private lan 10.x", "tcp", "10.0.0.1:9051", true, "security violation: raw connection attempted to non-loopback destination"},
		{"private lan 172.16", "tcp", "172.16.0.1:9051", true, "security violation: raw connection attempted to non-loopback destination"},
		{"public ip 8.8.8.8", "tcp", "8.8.8.8:9051", true, "security violation: raw connection attempted to non-loopback destination"},
		{"public ip 1.1.1.1", "tcp", "1.1.1.1:9051", true, "security violation: raw connection attempted to non-loopback destination"},
		{"remote ipv6", "tcp", "[2001:db8::1]:9051", true, "security violation: raw connection attempted to non-loopback destination"},
		{"link-local ipv6", "tcp", "[fe80::1]:9051", true, "security violation: raw connection attempted to non-loopback destination"},
		{"malformed address no port", "tcp", "127.0.0.1", true, "security violation: invalid socket address"},
		{"malformed address empty", "tcp", "", true, "security violation: invalid socket address"},
		{"malformed address text", "tcp", "invalid-format", true, "security violation: invalid socket address"},
		{"unix socket non-existent absolute fails closed", "unix", "/var/run/tor/control", true, "security violation: unix control socket"},
		{"unix socket relative rejected", "unix", "control.sock", true, "security violation: unix socket path must be absolute"},
		{"unix socket null byte rejected", "unix", "/var/run\x00/control", true, "security violation: unix socket path contains null byte"},
		{"unsupported network udp rejected", "udp", "127.0.0.1:9051", true, "security violation: unsupported network"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDestinationAddress(tc.network, tc.address)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error for address %q, got nil", tc.address)
				}
				if !strings.Contains(err.Error(), tc.errorSubstr) {
					t.Errorf("expected error containing %q, got: %v", tc.errorSubstr, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for permitted address %q: %v", tc.address, err)
				}
			}
		})
	}
}

type mockTestResolver struct {
	lookupFn func(ctx context.Context, network, host string) ([]net.IP, error)
}

func (m *mockTestResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if m.lookupFn != nil {
		return m.lookupFn(ctx, network, host)
	}
	return nil, errors.New("unconfigured mock resolver")
}

func TestResolveAndValidateEndpoint_ProductionFunction(t *testing.T) {
	ctx := context.Background()

	t.Run("IPv4LoopbackLiteralDirect", func(t *testing.T) {
		res, err := ResolveAndValidateEndpoint(ctx, "127.0.0.1:9051", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != "127.0.0.1:9051" {
			t.Errorf("expected 127.0.0.1:9051, got %s", res)
		}
	})

	t.Run("IPv6LoopbackLiteralDirect", func(t *testing.T) {
		res, err := ResolveAndValidateEndpoint(ctx, "[::1]:9051", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != "[::1]:9051" {
			t.Errorf("expected [::1]:9051, got %s", res)
		}
	})

	t.Run("NonLoopbackLiteralRejected", func(t *testing.T) {
		_, err := ResolveAndValidateEndpoint(ctx, "192.168.1.1:9051", nil)
		if err == nil {
			t.Fatal("expected error for non-loopback literal, got nil")
		}
		if !strings.Contains(err.Error(), "security violation: remote tor endpoint") {
			t.Errorf("expected security violation error, got: %v", err)
		}
	})

	t.Run("HostnameResolvingToIPv4Loopback", func(t *testing.T) {
		mockRes := &mockTestResolver{
			lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			},
		}
		res, err := ResolveAndValidateEndpoint(ctx, "localhost:9051", mockRes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != "127.0.0.1:9051" {
			t.Errorf("expected 127.0.0.1:9051, got %s", res)
		}
	})

	t.Run("HostnameResolvingToIPv6Loopback", func(t *testing.T) {
		mockRes := &mockTestResolver{
			lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("::1")}, nil
			},
		}
		res, err := ResolveAndValidateEndpoint(ctx, "localhost:9051", mockRes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != "[::1]:9051" {
			t.Errorf("expected [::1]:9051, got %s", res)
		}
	})

	t.Run("HostnameResolvingToDualStackLoopbackPrefersIPv4", func(t *testing.T) {
		mockRes := &mockTestResolver{
			lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")}, nil
			},
		}
		res, err := ResolveAndValidateEndpoint(ctx, "localhost:9051", mockRes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != "127.0.0.1:9051" {
			t.Errorf("expected IPv4 loopback preferred '127.0.0.1:9051', got %s", res)
		}
	})

	t.Run("HostnameResolvingToNonLoopbackRejected", func(t *testing.T) {
		mockRes := &mockTestResolver{
			lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("10.0.0.50")}, nil
			},
		}
		_, err := ResolveAndValidateEndpoint(ctx, "remote-tor.internal:9051", mockRes)
		if err == nil {
			t.Fatal("expected error for non-loopback resolution, got nil")
		}
		if !strings.Contains(err.Error(), "security violation: tor host") || !strings.Contains(err.Error(), "resolved to non-loopback address 10.0.0.50") {
			t.Errorf("expected security violation for non-loopback resolution, got: %v", err)
		}
	})

	t.Run("HostnameResolvingToMixedLoopbackAndNonLoopbackRejected", func(t *testing.T) {
		mockRes := &mockTestResolver{
			lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.50")}, nil
			},
		}
		_, err := ResolveAndValidateEndpoint(ctx, "mixed-tor.local:9051", mockRes)
		if err == nil {
			t.Fatal("expected error for mixed DNS resolution, got nil")
		}
		if !strings.Contains(err.Error(), "security violation: tor host") || !strings.Contains(err.Error(), "resolved to non-loopback address 192.168.1.50") {
			t.Errorf("expected security violation for mixed resolution, got: %v", err)
		}
	})

	t.Run("HostnameResolutionErrorFailsClosed", func(t *testing.T) {
		mockRes := &mockTestResolver{
			lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return nil, errors.New("nxdomain: name not found")
			},
		}
		_, err := ResolveAndValidateEndpoint(ctx, "nonexistent-tor.local:9051", mockRes)
		if err == nil {
			t.Fatal("expected error on DNS resolution failure, got nil")
		}
		if !strings.Contains(err.Error(), "failed to resolve tor host") {
			t.Errorf("expected 'failed to resolve tor host' error, got: %v", err)
		}
	})

	t.Run("HostnameResolutionEmptyFailsClosed", func(t *testing.T) {
		mockRes := &mockTestResolver{
			lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return []net.IP{}, nil
			},
		}
		_, err := ResolveAndValidateEndpoint(ctx, "empty-tor.local:9051", mockRes)
		if err == nil {
			t.Fatal("expected error on empty DNS resolution, got nil")
		}
		if !strings.Contains(err.Error(), "no IP addresses returned") {
			t.Errorf("expected 'no IP addresses returned' error, got: %v", err)
		}
	})

	t.Run("PortBoundaries", func(t *testing.T) {
		portCases := []struct {
			endpoint    string
			expectError bool
		}{
			{"127.0.0.1:0", true},
			{"127.0.0.1:65536", true},
			{"127.0.0.1:-1", true},
			{"127.0.0.1:abc", true},
			{"127.0.0.1:1", false},
			{"127.0.0.1:65535", false},
		}

		for _, pc := range portCases {
			_, err := ResolveAndValidateEndpoint(ctx, pc.endpoint, nil)
			if pc.expectError && err == nil {
				t.Errorf("expected error for endpoint %q, got nil", pc.endpoint)
			}
			if !pc.expectError && err != nil {
				t.Errorf("unexpected error for endpoint %q: %v", pc.endpoint, err)
			}
		}
	})
}

func TestClientConnect_DialTargetUsesValidatedLoopbackIP(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = "localhost:9051"

	client := NewClient(cfg, nil)

	mockRes := &mockTestResolver{
		lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	}
	client.setResolver(mockRes)

	var dialedAddr string
	client.setDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialedAddr = addr
		return nil, errors.New("intercepted dial for test")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_ = client.Connect(ctx)

	// Verify that the dialer receives the validated loopback IP literal, NOT "localhost:9051"
	if dialedAddr != "127.0.0.1:9051" {
		t.Errorf("expected dialer to receive validated loopback IP literal '127.0.0.1:9051', got %q", dialedAddr)
	}
}

func TestClientConnect_NonLoopbackHostnameBlocked(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = "tampered-tor.internal:9051"

	client := NewClient(cfg, nil)

	mockRes := &mockTestResolver{
		lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.10.10.10")}, nil
		},
	}
	client.setResolver(mockRes)

	dialerCalled := false
	client.setDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialerCalled = true
		return nil, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := client.Connect(ctx)
	if err == nil {
		t.Fatal("expected Connect to fail for non-loopback hostname resolution, got nil")
	}
	if !strings.Contains(err.Error(), "security violation: tor host") || !strings.Contains(err.Error(), "resolved to non-loopback address 10.10.10.10") {
		t.Errorf("expected security violation error, got: %v", err)
	}
	if dialerCalled {
		t.Errorf("security violation: dialer was invoked for non-loopback destination")
	}
	if client.State() != StateDisconnected {
		t.Errorf("expected client state to remain StateDisconnected, got %s", client.State())
	}
}

func TestClientConnect_MixedDNSResultsBlocked(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = "mixed-tor.internal:9051"

	client := NewClient(cfg, nil)

	mockRes := &mockTestResolver{
		lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("172.16.5.5")}, nil
		},
	}
	client.setResolver(mockRes)

	dialerCalled := false
	client.setDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialerCalled = true
		return nil, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := client.Connect(ctx)
	if err == nil {
		t.Fatal("expected Connect to fail for mixed DNS resolution, got nil")
	}
	if !strings.Contains(err.Error(), "security violation: tor host") {
		t.Errorf("expected security violation error, got: %v", err)
	}
	if dialerCalled {
		t.Errorf("security violation: dialer was invoked for mixed DNS resolution")
	}
	if client.State() != StateDisconnected {
		t.Errorf("expected client state to remain StateDisconnected, got %s", client.State())
	}
}

func TestClientConnect_DNSResolutionFailure(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = "failing-dns.internal:9051"

	client := NewClient(cfg, nil)

	mockRes := &mockTestResolver{
		lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
			return nil, errors.New("simulated DNS network timeout")
		},
	}
	client.setResolver(mockRes)

	dialerCalled := false
	client.setDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialerCalled = true
		return nil, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := client.Connect(ctx)
	if err == nil {
		t.Fatal("expected Connect to fail for DNS resolution failure, got nil")
	}
	if !strings.Contains(err.Error(), "failed to resolve tor host") {
		t.Errorf("expected 'failed to resolve tor host' error, got: %v", err)
	}
	if dialerCalled {
		t.Errorf("dialer should not be invoked when DNS resolution fails")
	}
	if client.State() != StateDisconnected {
		t.Errorf("expected client state to remain StateDisconnected, got %s", client.State())
	}
}

func TestClientConnect_CustomDialerCannotBypassSecurity(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		mockIPs     []net.IP
		errorSubstr string
	}{
		{
			name:        "remote private ipv4 endpoint",
			endpoint:    "192.168.1.100:9051",
			errorSubstr: "security violation: remote tor endpoint",
		},
		{
			name:        "remote public ipv4 endpoint",
			endpoint:    "8.8.8.8:9051",
			errorSubstr: "security violation: remote tor endpoint",
		},
		{
			name:        "remote resolving hostname",
			endpoint:    "evil-remote.internal:9051",
			mockIPs:     []net.IP{net.ParseIP("192.168.10.10")},
			errorSubstr: "security violation: tor host",
		},
		{
			name:        "malformed endpoint format",
			endpoint:    "invalid-endpoint-format",
			errorSubstr: "invalid tor.control_endpoint",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Tor.ControlEndpoint = tc.endpoint

			client := NewClient(cfg, nil)

			if len(tc.mockIPs) > 0 {
				client.setResolver(&mockTestResolver{
					lookupFn: func(ctx context.Context, network, host string) ([]net.IP, error) {
						return tc.mockIPs, nil
					},
				})
			}

			dialerInvoked := false
			client.setDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialerInvoked = true
				return nil, errors.New("custom dialer should not be reached")
			})

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()

			err := client.Connect(ctx)
			if err == nil {
				t.Fatalf("expected error for endpoint %q, got nil", tc.endpoint)
			}
			if !strings.Contains(err.Error(), tc.errorSubstr) {
				t.Errorf("expected error containing %q, got: %v", tc.errorSubstr, err)
			}
			if dialerInvoked {
				t.Errorf("SECURITY FLAW: custom dialer was invoked for unverified/remote endpoint %q", tc.endpoint)
			}
			if client.State() != StateDisconnected {
				t.Errorf("expected client state to remain StateDisconnected, got %s", client.State())
			}
		})
	}
}

func TestClientConnect_ContextCancellationAndTimeout(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = "127.0.0.1:9051"

	t.Run("DefaultDialerPreCancelledContext", func(t *testing.T) {
		client := NewClient(cfg, nil)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := client.Connect(ctx)
		if err == nil {
			t.Fatal("expected error with pre-cancelled context, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got: %v", err)
		}
		if client.State() != StateDisconnected {
			t.Errorf("expected client state to remain StateDisconnected on cancelled context, got %s", client.State())
		}
	})

	t.Run("CustomDialerPreCancelledContext", func(t *testing.T) {
		client := NewClient(cfg, nil)
		dialerInvoked := false
		client.setDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialerInvoked = true
			return nil, nil
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := client.Connect(ctx)
		if err == nil {
			t.Fatal("expected error with pre-cancelled context on custom dialer, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got: %v", err)
		}
		if dialerInvoked {
			t.Errorf("custom dialer should not be invoked when context is already cancelled")
		}
		if client.State() != StateDisconnected {
			t.Errorf("expected client state to remain StateDisconnected, got %s", client.State())
		}
	})

	t.Run("CustomDialerContextCancelledDuringDial", func(t *testing.T) {
		client := NewClient(cfg, nil)
		ctx, cancel := context.WithCancel(context.Background())

		client.setDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			cancel() // cancel context during dial
			return nil, ctx.Err()
		})

		err := client.Connect(ctx)
		if err == nil {
			t.Fatal("expected error when context is cancelled during custom dial, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got: %v", err)
		}
		if client.State() != StateDisconnected {
			t.Errorf("expected client state to remain StateDisconnected, got %s", client.State())
		}
	})
}

func TestClientConnect_UnsupportedNetworkModes(t *testing.T) {
	unsupportedModes := []string{"udp", "http", "ws", "pipe", "raw"}
	for _, mode := range unsupportedModes {
		t.Run("mode_"+mode, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Tor.NetworkMode = mode
			client := NewClient(cfg, nil)

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()

			err := client.Connect(ctx)
			if err == nil {
				t.Fatalf("expected error for unsupported network mode %q, got nil", mode)
			}
			if !strings.Contains(err.Error(), "unsupported tor.network_mode") {
				t.Errorf("expected 'unsupported tor.network_mode' error, got: %v", err)
			}
		})
	}

	t.Run("unix_mode_empty_endpoint", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Tor.NetworkMode = "unix"
		cfg.Tor.ControlEndpoint = ""
		client := NewClient(cfg, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		err := client.Connect(ctx)
		if err == nil {
			t.Fatal("expected error for empty unix endpoint, got nil")
		}
		if !strings.Contains(err.Error(), "unix socket path must not be empty") {
			t.Errorf("expected empty unix socket path error, got: %v", err)
		}
	})

	t.Run("unix_mode_relative_endpoint_rejected", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Tor.NetworkMode = "unix"
		cfg.Tor.ControlEndpoint = "control.sock"
		client := NewClient(cfg, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		err := client.Connect(ctx)
		if err == nil {
			t.Fatal("expected error for relative unix endpoint, got nil")
		}
		if !strings.Contains(err.Error(), "must be absolute") {
			t.Errorf("expected relative unix socket path error, got: %v", err)
		}
	})
}

func TestValidateUnixEndpoint_Comprehensive(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("empty_endpoint_rejected", func(t *testing.T) {
		err := ValidateUnixEndpoint("")
		if err == nil || !strings.Contains(err.Error(), "must not be empty") {
			t.Errorf("expected empty error, got: %v", err)
		}
	})

	t.Run("null_byte_rejected", func(t *testing.T) {
		err := ValidateUnixEndpoint("/var/run/tor\x00/control")
		if err == nil || !strings.Contains(err.Error(), "null byte") {
			t.Errorf("expected null byte error, got: %v", err)
		}
	})

	t.Run("relative_path_rejected", func(t *testing.T) {
		err := ValidateUnixEndpoint("tor_control.sock")
		if err == nil || !strings.Contains(err.Error(), "must be absolute") {
			t.Errorf("expected absolute path error, got: %v", err)
		}
	})

	t.Run("relative_traversal_rejected", func(t *testing.T) {
		err := ValidateUnixEndpoint("../var/run/tor/control")
		if err == nil || !strings.Contains(err.Error(), "must be absolute") {
			t.Errorf("expected absolute path error, got: %v", err)
		}
	})

	t.Run("regular_file_rejected_as_socket", func(t *testing.T) {
		regularFilePath := filepath.Join(tempDir, "regular_file.txt")
		if err := os.WriteFile(regularFilePath, []byte("not a socket"), 0600); err != nil {
			t.Fatalf("failed to create regular file: %v", err)
		}
		err := ValidateUnixEndpoint(regularFilePath)
		if err == nil || !strings.Contains(err.Error(), "must be a socket") {
			t.Errorf("expected must be a socket error, got: %v", err)
		}
	})

	t.Run("directory_rejected_as_socket", func(t *testing.T) {
		dirPath := filepath.Join(tempDir, "somedir")
		if err := os.MkdirAll(dirPath, 0700); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		err := ValidateUnixEndpoint(dirPath)
		if err == nil || !strings.Contains(err.Error(), "must be a socket") {
			t.Errorf("expected must be a socket error, got: %v", err)
		}
	})

	t.Run("non_existent_path_fails_closed_by_default", func(t *testing.T) {
		nonExistentPath := filepath.Join(tempDir, "control.sock")
		err := ValidateUnixEndpoint(nonExistentPath)
		if err == nil {
			t.Fatal("expected error for non-existent unix socket, got nil")
		}
		if !strings.Contains(err.Error(), "unix control socket does not exist") {
			t.Errorf("expected 'unix control socket does not exist' error, got: %v", err)
		}
	})

	t.Run("non_existent_path_permitted_when_explicitly_requested", func(t *testing.T) {
		nonExistentPath := filepath.Join(tempDir, "control.sock")
		err := ValidateUnixEndpointWithRequirement(nonExistentPath, false)
		if err != nil {
			t.Errorf("expected permitted when mustExist=false, got: %v", err)
		}
	})

	t.Run("missing_parent_directory_fails_closed", func(t *testing.T) {
		missingParentPath := filepath.Join(tempDir, "non_existent_parent_dir", "control.sock")
		err := ValidateUnixEndpoint(missingParentPath)
		if err == nil {
			t.Fatal("expected error for missing parent directory, got nil")
		}
		if !strings.Contains(err.Error(), "directory does not exist") {
			t.Errorf("expected 'directory does not exist' error, got: %v", err)
		}
	})

	t.Run("parent_path_is_file_rejected", func(t *testing.T) {
		fakeParent := filepath.Join(tempDir, "fake_parent.txt")
		if err := os.WriteFile(fakeParent, []byte("parent"), 0600); err != nil {
			t.Fatalf("failed to create fake parent file: %v", err)
		}
		err := ValidateUnixEndpoint(filepath.Join(fakeParent, "control.sock"))
		if err == nil {
			t.Fatal("expected error when parent path is a regular file, got nil")
		}
		if !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("expected 'not a directory' error, got: %v", err)
		}
	})

	t.Run("world_writable_parent_directory_without_sticky_bit_rejected", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping POSIX permission test on Windows host")
		}
		wwDir := filepath.Join(tempDir, "world_writable_test_dir")
		if err := os.MkdirAll(wwDir, 0777); err != nil {
			t.Fatalf("failed to create test directory: %v", err)
		}
		_ = os.Chmod(wwDir, 0777)
		fi, err := os.Lstat(wwDir)
		if err == nil && (fi.Mode().Perm()&0002 != 0) && (fi.Mode()&os.ModeSticky == 0) {
			err = ValidateUnixEndpointWithRequirement(filepath.Join(wwDir, "control.sock"), false)
			if err == nil {
				t.Fatal("expected error for world-writable parent directory without sticky bit, got nil")
			}
			if !strings.Contains(err.Error(), "world-writable without sticky bit") {
				t.Errorf("expected 'world-writable without sticky bit' error, got: %v", err)
			}
		}
	})

	t.Run("symlink_socket_rejected", func(t *testing.T) {
		targetFile := filepath.Join(tempDir, "symlink_target.txt")
		if err := os.WriteFile(targetFile, []byte("target"), 0600); err != nil {
			t.Fatalf("failed to create target file: %v", err)
		}
		linkPath := filepath.Join(tempDir, "symlink_sock.sock")
		err := os.Symlink(targetFile, linkPath)
		if err != nil {
			t.Skipf("skipping symlink test: os.Symlink not permitted: %v", err)
		}
		defer os.Remove(linkPath)

		err = ValidateUnixEndpoint(linkPath)
		if err == nil {
			t.Fatal("expected error for symlink unix socket, got nil")
		}
		if !strings.Contains(err.Error(), "cannot be a symlink") {
			t.Errorf("expected 'cannot be a symlink' error, got: %v", err)
		}
	})

	t.Run("symlink_parent_directory_rejected", func(t *testing.T) {
		realSubdir := filepath.Join(tempDir, "real_subdir")
		if err := os.MkdirAll(realSubdir, 0700); err != nil {
			t.Fatalf("failed to create real subdir: %v", err)
		}
		linkDir := filepath.Join(tempDir, "symlink_dir")
		err := os.Symlink(realSubdir, linkDir)
		if err != nil {
			t.Skipf("skipping symlink parent dir test: os.Symlink not permitted: %v", err)
		}
		defer os.Remove(linkDir)

		err = ValidateUnixEndpointWithRequirement(filepath.Join(linkDir, "control.sock"), false)
		if err == nil {
			t.Fatal("expected error for symlink parent directory, got nil")
		}
		if !strings.Contains(err.Error(), "unauthorized symlink") && !strings.Contains(err.Error(), "cannot be a symlink") {
			t.Errorf("expected symlink error, got: %v", err)
		}
	})

	t.Run("symlink_ancestor_directory_rejected", func(t *testing.T) {
		realAncestor := filepath.Join(tempDir, "real_ancestor")
		nestedChild := filepath.Join(realAncestor, "nested_child")
		if err := os.MkdirAll(nestedChild, 0700); err != nil {
			t.Fatalf("failed to create nested child dir: %v", err)
		}
		linkAncestor := filepath.Join(tempDir, "link_ancestor")
		err := os.Symlink(realAncestor, linkAncestor)
		if err != nil {
			t.Skipf("skipping ancestor symlink test: os.Symlink not permitted: %v", err)
		}
		defer os.Remove(linkAncestor)

		// Path where the immediate parent (nested_child) is NOT a symlink,
		// but the intermediate ancestor (link_ancestor) IS a symlink.
		socketInNested := filepath.Join(linkAncestor, "nested_child", "control.sock")
		err = ValidateUnixEndpointWithRequirement(socketInNested, false)
		if err == nil {
			t.Fatal("expected error for symlink ancestor directory, got nil")
		}
		if !strings.Contains(err.Error(), "unauthorized symlink") {
			t.Errorf("expected 'unauthorized symlink' error, got: %v", err)
		}
	})

	t.Run("peer_verification_status_initial_and_unsupported", func(t *testing.T) {
		client := NewClient(nil, nil)
		if client.PeerVerificationStatus() != PeerVerificationNone {
			t.Errorf("expected initial PeerVerificationNone, got %s", client.PeerVerificationStatus())
		}
	})

	t.Run("require_peer_verification_policy_rejects_unsupported", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Tor.NetworkMode = "unix"
		cfg.Tor.ControlEndpoint = "/var/run/tor/control"
		cfg.Tor.RequirePeerVerification = true

		client := NewClient(cfg, nil)
		client.setDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			c1, _ := net.Pipe()
			return c1, nil
		})

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		err := client.Connect(ctx)
		if runtime.GOOS != "linux" {
			if err == nil {
				t.Fatal("expected error when strict peer verification required on unsupported platform, got nil")
			}
			if !strings.Contains(err.Error(), "strict unix peer verification required") && !strings.Contains(err.Error(), "security violation") {
				t.Errorf("expected strict peer verification error, got: %v", err)
			}
		}
	})

	t.Run("tcp_connection_with_require_peer_verification_permitted", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Tor.NetworkMode = "tcp"
		cfg.Tor.ControlEndpoint = "127.0.0.1:9051"
		cfg.Tor.RequirePeerVerification = true

		client := NewClient(cfg, nil)
		client.setDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			c1, _ := net.Pipe()
			return c1, nil
		})

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		err := client.Connect(ctx)
		if err != nil {
			t.Fatalf("expected TCP connection to succeed with RequirePeerVerification=true, got: %v", err)
		}
		defer client.Close()

		if client.PeerVerificationStatus() != PeerVerificationNone {
			t.Errorf("expected TCP peer verification status to remain PeerVerificationNone, got: %s", client.PeerVerificationStatus())
		}
	})

	t.Run("path_replacement_toctou_mitigation_detection", func(t *testing.T) {
		// Simulates a scenario where an initial check occurred, but the target path
		// was replaced before connection.
		sockPath := filepath.Join(tempDir, "toctou_test.sock")
		// Initially path does not exist -> fails closed
		if err := ValidateUnixEndpoint(sockPath); err == nil {
			t.Fatal("expected initial missing path to fail closed")
		}

		// Attacker creates a regular file instead of a socket
		if err := os.WriteFile(sockPath, []byte("injected evil regular file"), 0600); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}
		defer os.Remove(sockPath)

		// Subsequent validation must immediately detect and reject the substituted file
		err := ValidateUnixEndpoint(sockPath)
		if err == nil || !strings.Contains(err.Error(), "must be a socket") {
			t.Fatalf("expected substituted regular file to be rejected as not a socket, got: %v", err)
		}
	})
}

func TestTorClient_IdleConnectionAndSubsequentCommand(t *testing.T) {
	server, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	// Configure short connection timeout to prove handshake deadline does not linger and kill idle socket
	cfg.Tor.ConnectionTimeout = 150 * time.Millisecond

	logger, _ := logging.New(logging.Options{LogToConsole: false, LogToFile: false})
	client := server.Client(cfg, logger)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	authResult, err := client.ConnectAndAuthenticate(ctx)
	if err != nil {
		t.Fatalf("ConnectAndAuthenticate failed: %v", err)
	}
	if !authResult.Success {
		t.Fatalf("expected auth success, got: %s", authResult.Error)
	}

	// Sit idle for 300ms, which exceeds the 150ms handshake timeout
	time.Sleep(300 * time.Millisecond)

	// Verify client remains authenticated and did not drop or timeout
	if client.State() != StateAuthenticated {
		t.Fatalf("expected client state to remain StateAuthenticated during idle, got: %s", client.State())
	}

	// Execute command after idle period
	version, err := client.GetVersion(ctx)
	if err != nil {
		t.Fatalf("GetVersion failed after idle period: %v", err)
	}
	if version != "0.4.8.10" {
		t.Errorf("expected version 0.4.8.10, got %q", version)
	}
}

func TestTorClient_IdleConnectionAsyncEvent(t *testing.T) {
	server, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Tor.ControlEndpoint = server.Addr()
	cfg.Tor.CookiePath = server.CookiePath()
	cfg.Tor.ConnectionTimeout = 200 * time.Millisecond

	logger, _ := logging.New(logging.Options{LogToConsole: false, LogToFile: false})
	client := server.Client(cfg, logger)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := client.ConnectAndAuthenticate(ctx); err != nil {
		t.Fatalf("ConnectAndAuthenticate failed: %v", err)
	}

	eventCh, err := client.SubscribeEvents(ctx, "STATUS_CLIENT")
	if err != nil {
		t.Fatalf("SubscribeEvents failed: %v", err)
	}

	// Sit idle
	time.Sleep(250 * time.Millisecond)

	// Broadcast async event
	server.BroadcastAsyncEvent("650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"")

	select {
	case evt := <-eventCh:
		if evt.Type != "STATUS_CLIENT" {
			t.Errorf("expected event type STATUS_CLIENT, got: %s", evt.Type)
		}
		if evt.Severity != "NOTICE" {
			t.Errorf("expected severity NOTICE, got: %s", evt.Severity)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for async event on idle connection")
	}
}

func TestTorProtocol_AggregateLimitsEnforced(t *testing.T) {
	t.Run("single_line_exceeds_max_line_length", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		go func() {
			oversized := strings.Repeat("X", MaxLineLength+10) + "\r\n"
			_, _ = io.WriteString(c2, oversized)
		}()

		_, err := readSingleLineResponse(c1, 500*time.Millisecond)
		if err == nil {
			t.Fatal("expected error on oversized line, got nil")
		}
		if !errors.Is(err, ErrProtocolViolation) {
			t.Errorf("expected ErrProtocolViolation, got: %v", err)
		}
	})

	t.Run("aggregate_response_bytes_exceeds_limit", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		go func() {
			chunk := "250-" + strings.Repeat("A", 32768) + "\r\n"
			for i := 0; i < 35; i++ {
				_, err := io.WriteString(c2, chunk)
				if err != nil {
					return
				}
			}
			_, _ = io.WriteString(c2, "250 OK\r\n")
		}()

		_, err := readMultilineResponse(c1, 1*time.Second)
		if err == nil {
			t.Fatal("expected error on oversized aggregate response, got nil")
		}
		if !errors.Is(err, ErrProtocolViolation) {
			t.Errorf("expected ErrProtocolViolation, got: %v", err)
		}
	})

	t.Run("response_line_count_exceeds_max_lines", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		go func() {
			for i := 0; i < MaxResponseLines+10; i++ {
				_, err := io.WriteString(c2, "250-line\r\n")
				if err != nil {
					return
				}
			}
			_, _ = io.WriteString(c2, "250 OK\r\n")
		}()

		_, err := readMultilineResponse(c1, 1*time.Second)
		if err == nil {
			t.Fatal("expected error on excessive response line count, got nil")
		}
		if !errors.Is(err, ErrProtocolViolation) {
			t.Errorf("expected ErrProtocolViolation, got: %v", err)
		}
	})
}
