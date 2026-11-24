package tor

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/config"
	"github.com/rishii-sudo/privacy-gateway/internal/logging"
)

// MockTorServer simulates a local Tor Control Port server for deterministic testing and verification.
type MockTorServer struct {
	listener           net.Listener
	addr               string
	tempDir            string
	cookieFile         string
	cookieData         []byte
	serverNonce        []byte
	lastClientNonce    []byte
	mu                 sync.Mutex
	conns              []net.Conn
	dialer             func(ctx context.Context, network, addr string) (net.Conn, error)
	corruptServerHash  bool
	rejectAuth         bool
	hangAuthChallenge  bool
	hangCommands       bool
	customAuthMethods  string
	customVersion      string
	bootstrapStatus    string
	circuitEstablished string
	circuitStatus      string
	socksListeners     string
	closed             chan struct{}
}

// NewInMemoryMockTorServer creates a mock Tor server operating over an in-memory net.Pipe.
// This allows sandbox-isolated test execution without requiring OS network socket permissions.
func NewInMemoryMockTorServer() (*MockTorServer, func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	tempDir, err := os.MkdirTemp("", "tor-mock-inmem-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp dir for mock tor: %w", err)
	}

	cookieData := make([]byte, CookieSize)
	if _, err := io.ReadFull(rand.Reader, cookieData); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, nil, fmt.Errorf("failed to generate mock cookie: %w", err)
	}

	cookiePath := filepath.Join(tempDir, "control_auth_cookie")
	if err := os.WriteFile(cookiePath, cookieData, 0600); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, nil, fmt.Errorf("failed to write mock cookie: %w", err)
	}

	serverNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, serverNonce); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, nil, fmt.Errorf("failed to generate server nonce: %w", err)
	}

	s := &MockTorServer{
		addr:               "127.0.0.1:9051",
		tempDir:            tempDir,
		cookieFile:         cookiePath,
		cookieData:         cookieData,
		serverNonce:        serverNonce,
		customVersion:      "0.4.8.10",
		bootstrapStatus:    "NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"",
		circuitEstablished: "1",
		circuitStatus:      "1 BUILT $1111111111111111111111111111111111111111~Guard,$2222222222222222222222222222222222222222~Exit BUILD_FLAGS=IS_INTERNAL PURPOSE=GENERAL TIME_CREATED=2026-11-18T00:00:00",
		socksListeners:     "\"127.0.0.1:9050\"",
		closed:             make(chan struct{}),
	}

	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		cConn, sConn := net.Pipe()
		s.mu.Lock()
		s.conns = append(s.conns, sConn)
		s.mu.Unlock()
		go s.handleConn(sConn)
		return cConn, nil
	}
	s.dialer = dialer

	return s, dialer, nil
}

// Client creates a Client pre-wired to this mock server via private dependency injection.
// This allows deterministic in-memory testing across test packages without exposing
// unrestricted public dialer mutators on Client in production.
func (s *MockTorServer) Client(cfg *config.Config, logger *logging.Logger) *Client {
	c := NewClient(cfg, logger)
	c.setDialer(s.dialer)
	return c
}

func (s *MockTorServer) Addr() string {
	return s.addr
}

func (s *MockTorServer) CookiePath() string {
	return s.cookieFile
}

func (s *MockTorServer) SetCorruptServerHash(corrupt bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.corruptServerHash = corrupt
}

func (s *MockTorServer) SetAuthMethods(methods string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.customAuthMethods = methods
}

func (s *MockTorServer) SetRejectAuth(reject bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectAuth = reject
}

func (s *MockTorServer) SetHangCommands(hang bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hangCommands = hang
}

func (s *MockTorServer) SetBootstrapStatus(progress int, tag, summary string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bootstrapStatus = fmt.Sprintf("NOTICE BOOTSTRAP PROGRESS=%d TAG=%s SUMMARY=%q", progress, tag, summary)
}

func (s *MockTorServer) SetCircuits(circuitStatus string, established bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.circuitStatus = circuitStatus
	if established {
		s.circuitEstablished = "1"
	} else {
		s.circuitEstablished = "0"
	}
}

func (s *MockTorServer) Close() {
	s.mu.Lock()
	select {
	case <-s.closed:
		s.mu.Unlock()
		return
	default:
		close(s.closed)
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	_ = os.RemoveAll(s.tempDir)
}

func (s *MockTorServer) handleConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	authenticated := false

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		cmd := strings.TrimRight(line, "\r\n")
		parts := strings.Split(cmd, " ")
		action := strings.ToUpper(parts[0])

		switch action {
		case "PROTOCOLINFO":
			s.mu.Lock()
			ver := s.customVersion
			cookiePath := s.cookieFile
			methods := s.customAuthMethods
			if methods == "" {
				methods = "COOKIE,SAFECOOKIE"
			}
			s.mu.Unlock()

			resp := fmt.Sprintf("250-PROTOCOLINFO 1\r\n250-AUTH METHODS=%s COOKIEFILE=%q\r\n250-VERSION Tor=%q\r\n250 OK\r\n", methods, cookiePath, ver)
			_, _ = io.WriteString(conn, resp)

		case "AUTHCHALLENGE":
			s.mu.Lock()
			hang := s.hangAuthChallenge
			corrupt := s.corruptServerHash
			cookie := make([]byte, len(s.cookieData))
			copy(cookie, s.cookieData)
			sNonce := make([]byte, len(s.serverNonce))
			copy(sNonce, s.serverNonce)
			s.mu.Unlock()

			if hang {
				time.Sleep(3 * time.Second)
			}

			if len(parts) < 3 || strings.ToUpper(parts[1]) != "SAFECOOKIE" {
				_, _ = io.WriteString(conn, "512 Syntax error in AUTHCHALLENGE\r\n")
				continue
			}

			clientNonceHex := parts[2]
			clientNonce, err := hex.DecodeString(clientNonceHex)
			if err != nil || len(clientNonce) != NonceSize {
				_, _ = io.WriteString(conn, "512 Invalid client nonce\r\n")
				continue
			}

			s.mu.Lock()
			s.lastClientNonce = clientNonce
			s.mu.Unlock()

			mac := hmac.New(sha256.New, []byte(ServerHashKey))
			mac.Write(cookie)
			mac.Write(clientNonce)
			mac.Write(sNonce)
			serverHash := mac.Sum(nil)

			if corrupt {
				serverHash[0] ^= 0xFF
			}

			resp := fmt.Sprintf("250 AUTHCHALLENGE SERVERHASH=%s SERVERNONCE=%s\r\n",
				hex.EncodeToString(serverHash),
				hex.EncodeToString(sNonce),
			)
			_, _ = io.WriteString(conn, resp)

		case "AUTHENTICATE":
			s.mu.Lock()
			reject := s.rejectAuth
			cookie := make([]byte, len(s.cookieData))
			copy(cookie, s.cookieData)
			cNonce := make([]byte, len(s.lastClientNonce))
			copy(cNonce, s.lastClientNonce)
			sNonce := make([]byte, len(s.serverNonce))
			copy(sNonce, s.serverNonce)
			s.mu.Unlock()

			if reject {
				_, _ = io.WriteString(conn, "515 Authentication failed: invalid client hash\r\n")
				continue
			}

			if len(parts) < 2 {
				_, _ = io.WriteString(conn, "515 Authentication required\r\n")
				continue
			}

			clientHashHex := parts[1]
			clientHash, err := hex.DecodeString(clientHashHex)
			if err != nil {
				_, _ = io.WriteString(conn, "515 Malformed client hash hex\r\n")
				continue
			}

			mac := hmac.New(sha256.New, []byte(ClientHashKey))
			mac.Write(cookie)
			mac.Write(cNonce)
			mac.Write(sNonce)
			expectedClientHash := mac.Sum(nil)

			if !hmac.Equal(clientHash, expectedClientHash) {
				_, _ = io.WriteString(conn, "515 Authentication failed: HMAC verification mismatch\r\n")
				continue
			}

			authenticated = true
			_, _ = io.WriteString(conn, "250 OK\r\n")

		case "GETINFO":
			s.mu.Lock()
			hang := s.hangCommands
			s.mu.Unlock()

			if hang {
				time.Sleep(3 * time.Second)
			}

			if !authenticated {
				_, _ = io.WriteString(conn, "514 Authentication required\r\n")
				continue
			}

			if len(parts) < 2 {
				_, _ = io.WriteString(conn, "512 Missing GETINFO parameter\r\n")
				continue
			}

			param := parts[1]
			s.mu.Lock()
			switch param {
			case "version":
				resp := fmt.Sprintf("250-version=%s\r\n250 OK\r\n", s.customVersion)
				s.mu.Unlock()
				_, _ = io.WriteString(conn, resp)
			case "status/bootstrap-phase":
				resp := fmt.Sprintf("250-status/bootstrap-phase=%s\r\n250 OK\r\n", s.bootstrapStatus)
				s.mu.Unlock()
				_, _ = io.WriteString(conn, resp)
			case "status/circuit-established":
				resp := fmt.Sprintf("250-status/circuit-established=%s\r\n250 OK\r\n", s.circuitEstablished)
				s.mu.Unlock()
				_, _ = io.WriteString(conn, resp)
			case "circuit-status":
				resp := fmt.Sprintf("250-circuit-status=%s\r\n250 OK\r\n", s.circuitStatus)
				s.mu.Unlock()
				_, _ = io.WriteString(conn, resp)
			case "net/listeners/socks":
				resp := fmt.Sprintf("250-net/listeners/socks=%s\r\n250 OK\r\n", s.socksListeners)
				s.mu.Unlock()
				_, _ = io.WriteString(conn, resp)
			default:
				s.mu.Unlock()
				_, _ = io.WriteString(conn, fmt.Sprintf("552 Unrecognized key %q\r\n", param))
			}

		case "SETEVENTS":
			if !authenticated {
				_, _ = io.WriteString(conn, "514 Authentication required\r\n")
				continue
			}
			_, _ = io.WriteString(conn, "250 OK\r\n")

		case "SIGNAL":
			_, _ = io.WriteString(conn, "250 OK\r\n")

		case "QUIT":
			_, _ = io.WriteString(conn, "250 closing connection\r\n")
			return

		default:
			_, _ = io.WriteString(conn, fmt.Sprintf("510 Unrecognized command %q\r\n", action))
		}
	}
}

// BroadcastAsyncEvent sends a 650 async event line to all connected clients.
func (s *MockTorServer) BroadcastAsyncEvent(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data := []byte(line + "\r\n")
	for _, c := range s.conns {
		_, _ = c.Write(data)
	}
}
