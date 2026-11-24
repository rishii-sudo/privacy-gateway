package tor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/config"
	"github.com/rishii-sudo/privacy-gateway/internal/logging"
)

// Client is the authoritative Go controller for local Tor daemon management.
type Client struct {
	cfg           *config.Config
	logger        *logging.Logger
	authenticator *Authenticator
	inspector     *InspectorBridge

	stateMu sync.RWMutex
	state   ControllerState

	connMu   sync.Mutex
	conn     net.Conn
	dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
	resolver IPResolver

	cmdMu     sync.Mutex
	replyChan chan []string

	subMu       sync.RWMutex
	subscribers map[chan Event]struct{}

	closeOnce sync.Once
	closeChan chan struct{}
	closeErr  error

	lastAuthMu     sync.RWMutex
	lastAuthResult *AuthResult

	peerVerifMu     sync.RWMutex
	peerVerifStatus PeerVerificationStatus

	monMu          sync.RWMutex
	droppedEvents  uint64
	totalEvents    uint64
	lastDropTime   time.Time
	isDegraded     bool
	degradedReason string
}

// NewClient creates an unauthenticated, un-connected Tor controller Client.
func NewClient(cfg *config.Config, logger *logging.Logger) *Client {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	return &Client{
		cfg:             cfg,
		logger:          logger,
		authenticator:   NewAuthenticator(cfg.Tor.ConnectionTimeout),
		inspector:       NewInspectorBridge(cfg.Tor.InspectorPath, cfg.Tor.InspectorTimeout),
		state:           StateDisconnected,
		peerVerifStatus: PeerVerificationNone,
		replyChan:       make(chan []string, 1),
		subscribers:     make(map[chan Event]struct{}),
		closeChan:       make(chan struct{}),
		resolver:        net.DefaultResolver,
	}
}

// State returns the current lifecycle state of the controller.
func (c *Client) State() ControllerState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

func (c *Client) setState(s ControllerState) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.state = s
}

// PeerVerificationStatus returns the peer credential verification status of the current or last Unix connection.
func (c *Client) PeerVerificationStatus() PeerVerificationStatus {
	c.peerVerifMu.RLock()
	defer c.peerVerifMu.RUnlock()
	return c.peerVerifStatus
}

// IPResolver defines an interface for resolving hostnames to IP addresses.
// It matches net.DefaultResolver's LookupIP method.
type IPResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// ValidateDestinationAddress verifies that a target network socket destination is strictly a loopback address
// for TCP connections or a secure absolute socket path for Unix domain sockets.
// This is used by net.Dialer.Control and custom dialer boundaries to enforce socket-level loopback guarantees.
func ValidateDestinationAddress(network, address string) error {
	if strings.HasPrefix(network, "tcp") {
		tcpHost, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("security violation: invalid socket address %q: %w", address, err)
		}
		destIP := net.ParseIP(tcpHost)
		if destIP == nil || !destIP.IsLoopback() {
			return fmt.Errorf("security violation: raw connection attempted to non-loopback destination %q", address)
		}
	} else if strings.HasPrefix(network, "unix") {
		return ValidateUnixEndpoint(address)
	} else {
		return fmt.Errorf("security violation: unsupported network %q", network)
	}
	return nil
}

// ValidateUnixEndpoint verifies that a Unix domain socket path is well-formed, absolute,
// exists as an actual socket file, has secure permissions, and resides in a safe directory.
// By default, it fails closed if the socket does not exist.
func ValidateUnixEndpoint(endpoint string) error {
	return ValidateUnixEndpointWithRequirement(endpoint, true)
}

// ValidateUnixEndpointWithRequirement validates a Unix domain socket path with an explicit
// requirement of whether the socket must already exist on disk.
// Set mustExist to true for production connection paths to fail closed if the socket is missing.
// Set mustExist to false only if the caller workflow explicitly permits a deferred or missing socket.
func ValidateUnixEndpointWithRequirement(endpoint string, mustExist bool) error {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return fmt.Errorf("invalid tor.control_endpoint: unix socket path must not be empty")
	}
	if strings.Contains(trimmed, "\x00") {
		return fmt.Errorf("security violation: unix socket path contains null byte: %q", endpoint)
	}

	cleanPath := filepath.Clean(trimmed)
	// Must be an absolute path to prevent working directory hijacks
	if !filepath.IsAbs(cleanPath) && !strings.HasPrefix(cleanPath, "/") && !strings.HasPrefix(cleanPath, "\\") {
		return fmt.Errorf("security violation: unix socket path must be absolute, got %q", endpoint)
	}

	// Inspect every ancestor directory component from root to immediate parent.
	// This prevents an attacker from substituting an intermediate ancestor directory with a symlink.
	parentDir := filepath.Dir(cleanPath)
	var ancestors []string
	curr := parentDir
	for {
		ancestors = append(ancestors, curr)
		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}
	// Reverse so we validate from root down to parentDir
	for i, j := 0, len(ancestors)-1; i < j; i, j = i+1, j-1 {
		ancestors[i], ancestors[j] = ancestors[j], ancestors[i]
	}

	for _, ancestor := range ancestors {
		// Skip root directory itself ("/" or "C:\" or "\\") as root cannot be a symlink
		if ancestor == filepath.Dir(ancestor) {
			continue
		}

		aFi, err := os.Lstat(ancestor)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("security violation: unix control socket ancestor directory does not exist: %q: %w", ancestor, err)
			}
			if errors.Is(err, os.ErrPermission) {
				return fmt.Errorf("security violation: permission denied inspecting ancestor directory %q: %w", ancestor, err)
			}
			return fmt.Errorf("failed to inspect ancestor directory %q of unix control socket: %w", ancestor, err)
		}

		if aFi.Mode()&os.ModeSymlink != 0 {
			// Check if this is an approved OS-level distribution symlink (e.g. /var/run -> /run on Linux)
			if !isSystemSymlinkAllowed(aFi, ancestor) {
				return fmt.Errorf("security violation: unix control socket ancestor directory is an unauthorized symlink: %q", ancestor)
			}
		} else if !aFi.IsDir() {
			return fmt.Errorf("security violation: unix control socket ancestor path is not a directory: %q", ancestor)
		}

		// Reject world-writable ancestor directories unless sticky bit is set (e.g. /tmp).
		if runtime.GOOS != "windows" {
			if aFi.Mode().Perm()&0002 != 0 && aFi.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("security violation: unix control socket ancestor directory is world-writable without sticky bit: %q", ancestor)
			}
		}

		if err := validateUnixAncestorDirPlatform(aFi, ancestor); err != nil {
			return err
		}
	}

	// Inspect the target socket file.
	fi, err := os.Lstat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			if mustExist {
				return fmt.Errorf("security violation: unix control socket does not exist: %q: %w", endpoint, err)
			}
			return nil
		}
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("security violation: permission denied inspecting unix control socket: %q: %w", endpoint, err)
		}
		return fmt.Errorf("failed to inspect unix control socket %q: %w", endpoint, err)
	}

	// 1. Symlink check: Unix control socket must not be a symlink
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("security violation: unix control socket cannot be a symlink: %q", endpoint)
	}

	// 2. File type check: Must be a socket (os.ModeSocket)
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("security violation: unix control socket must be a socket, got %s: %q", fi.Mode().Type(), endpoint)
	}

	// 3. Permissions check: World access is strictly prohibited (0007)
	if runtime.GOOS != "windows" {
		if fi.Mode().Perm()&0002 != 0 {
			return fmt.Errorf("security violation: unix control socket has insecure world-writable permissions (%04o): %q", fi.Mode().Perm(), endpoint)
		}
		if fi.Mode().Perm()&0004 != 0 {
			return fmt.Errorf("security violation: unix control socket has insecure world-readable permissions (%04o): %q", fi.Mode().Perm(), endpoint)
		}
		if fi.Mode().Perm()&0001 != 0 {
			return fmt.Errorf("security violation: unix control socket has insecure world-executable permissions (%04o): %q", fi.Mode().Perm(), endpoint)
		}
	}

	// 4. Platform-specific ownership check
	if err := validateUnixSocketPlatform(fi, cleanPath); err != nil {
		return err
	}

	return nil
}

// ResolveAndValidateEndpoint validates that the endpoint specifies a loopback target with a valid port (1-65535).
// If a hostname is specified, it resolves the host using the provided resolver and validates that ALL returned
// IP addresses are loopback addresses. It returns a dial target with a validated loopback IP literal and the
// configured port, avoiding any secondary DNS lookup during actual dialing.
func ResolveAndValidateEndpoint(ctx context.Context, endpoint string, resolver IPResolver) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid tor.control_endpoint %q: %w", endpoint, err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("invalid tor.control_endpoint %q: port must be a number between 1 and 65535", endpoint)
	}

	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if !ip.IsLoopback() {
			return "", fmt.Errorf("security violation: remote tor endpoint %q rejected; only loopback is permitted", endpoint)
		}
		return net.JoinHostPort(ip.String(), port), nil
	}

	// Hostname resolution: resolve and verify all addresses are loopback
	ips, resolveErr := resolver.LookupIP(ctx, "ip", host)
	if resolveErr != nil {
		return "", fmt.Errorf("failed to resolve tor host %q: %w", host, resolveErr)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("failed to resolve tor host %q: no IP addresses returned", host)
	}

	for _, resolvedIP := range ips {
		if !resolvedIP.IsLoopback() {
			return "", fmt.Errorf("security violation: tor host %q resolved to non-loopback address %s", host, resolvedIP.String())
		}
	}

	// Prefer IPv4 loopback if available, otherwise use first loopback address (e.g. IPv6 ::1)
	var chosenIP net.IP
	for _, resolvedIP := range ips {
		if resolvedIP.To4() != nil {
			chosenIP = resolvedIP
			break
		}
	}
	if chosenIP == nil {
		chosenIP = ips[0]
	}

	return net.JoinHostPort(chosenIP.String(), port), nil
}

// Connect establishes a connection to the configured local Tor control endpoint.
// It strictly validates loopback locality before connecting and dials the validated
// loopback IP literal directly to prevent DNS rebinding or TOCTOU resolution shifts.
func (c *Client) Connect(ctx context.Context) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	if c.State() != StateDisconnected && c.State() != StateClosed {
		return ErrAlreadyConnected
	}

	endpoint := c.cfg.Tor.ControlEndpoint
	networkMode := c.cfg.Tor.NetworkMode
	if networkMode == "" {
		networkMode = "tcp"
	}

	if networkMode != "tcp" && networkMode != "unix" {
		return fmt.Errorf("unsupported tor.network_mode %q: must be tcp or unix", networkMode)
	}

	dialTarget := endpoint
	if networkMode == "unix" {
		if err := ValidateUnixEndpoint(endpoint); err != nil {
			return err
		}
	} else {
		target, err := ResolveAndValidateEndpoint(ctx, endpoint, c.resolver)
		if err != nil {
			return err
		}
		dialTarget = target
	}

	c.setState(StateConnecting)

	var conn net.Conn
	var err error
	if c.dialFunc != nil {
		// Enforce destination socket address validation before delegating to custom dialer.
		// This guarantees that a custom dialer cannot accidentally bypass production loopback enforcement.
		if err := ValidateDestinationAddress(networkMode, dialTarget); err != nil {
			c.setState(StateDisconnected)
			return err
		}
		conn, err = c.dialFunc(ctx, networkMode, dialTarget)
	} else {
		dialer := net.Dialer{
			Timeout: c.cfg.Tor.ConnectionTimeout,
			Control: func(network, address string, rc syscall.RawConn) error {
				return ValidateDestinationAddress(network, address)
			},
		}
		conn, err = dialer.DialContext(ctx, networkMode, dialTarget)
	}

	if err != nil {
		c.setState(StateDisconnected)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("failed to connect to tor control endpoint %q: %w", endpoint, err)
	}

	// Post-connect peer credentials verification:
	// Mitigates residual TOCTOU races between pre-dial Lstat validation and connect().
	// On supported Unix platforms (Linux via SO_PEERCRED), this verifies the peer process UID.
	// On unsupported platforms (Windows, macOS), an explicit status of PeerVerificationUnsupported
	// is recorded so callers and diagnostics never silently assume peer verification occurred.
	if networkMode == "unix" && conn != nil {
		status, peerErr := verifyUnixPeer(conn)
		c.peerVerifMu.Lock()
		c.peerVerifStatus = status
		c.peerVerifMu.Unlock()

		if peerErr != nil {
			conn.Close()
			c.setState(StateDisconnected)
			if c.logger != nil {
				c.logger.Error(logging.CategoryTor, "tor-client", fmt.Sprintf("Unix socket peer credential verification failed: %v", peerErr))
			}
			return peerErr
		}

		if status == PeerVerificationUnsupported && c.logger != nil {
			c.logger.Warn(logging.CategoryTor, "tor-client", fmt.Sprintf("Unix socket peer credential verification is unsupported on %s; relying strictly on directory containment", runtime.GOOS))
		}

		if c.cfg.Tor.RequirePeerVerification && status != PeerVerificationVerified {
			conn.Close()
			c.setState(StateDisconnected)
			if c.logger != nil {
				c.logger.Error(logging.CategoryTor, "tor-client", fmt.Sprintf("Unix socket peer credential verification is required by policy but status is %s", status))
			}
			return fmt.Errorf("security violation: strict unix peer verification required by configuration, but status is %s", status)
		}
	}

	c.conn = conn
	c.closeChan = make(chan struct{})
	c.closeOnce = sync.Once{}

	return nil
}

// setDialer configures a custom dialer for connection establishment (private test seam).
func (c *Client) setDialer(fn func(ctx context.Context, network, addr string) (net.Conn, error)) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	c.dialFunc = fn
}

// setResolver configures a custom IPResolver for hostname resolution (private test seam).
func (c *Client) setResolver(r IPResolver) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	c.resolver = r
}

// ConnectAndAuthenticate connects to the control endpoint and performs SAFECOOKIE authentication.
func (c *Client) ConnectAndAuthenticate(ctx context.Context) (*AuthResult, error) {
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	return c.Authenticate(ctx)
}

// Authenticate performs protocol negotiation and SAFECOOKIE authentication.
func (c *Client) Authenticate(ctx context.Context) (*AuthResult, error) {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil || c.State() == StateDisconnected || c.State() == StateClosed {
		return nil, ErrNotConnected
	}

	c.setState(StateProtocolInfo)

	// Step 1: PROTOCOLINFO
	protoInfo, err := c.authenticator.NegotiateProtocol(conn)
	if err != nil {
		c.setState(StateDisconnected)
		_ = conn.Close()
		return nil, fmt.Errorf("protocol negotiation failed: %w", err)
	}

	// Verify SAFECOOKIE is supported (mandatory by default; no downgrade to NULL or HASHEDPASSWORD permitted)
	hasSafeCookie := false
	for _, m := range protoInfo.AuthMethods {
		if strings.EqualFold(m, "SAFECOOKIE") {
			hasSafeCookie = true
			break
		}
	}

	if !hasSafeCookie {
		c.setState(StateDisconnected)
		_ = conn.Close()
		return &AuthResult{
			Success:  false,
			Method:   "UNSUPPORTED",
			Endpoint: conn.RemoteAddr().String(),
			Error:    fmt.Sprintf("SAFECOOKIE authentication required by default, but not advertised by daemon (advertised: %s; downgrade prohibited)", strings.Join(protoInfo.AuthMethods, ", ")),
		}, fmt.Errorf("%w: mandatory SAFECOOKIE not supported by daemon (downgrade prohibited)", ErrAuthFailed)
	}

	cookiePath := c.cfg.Tor.CookiePath
	if cookiePath == "" {
		cookiePath = protoInfo.CookieFile
	}

	c.setState(StateChallenging)

	// Step 2: SAFECOOKIE challenge & authenticate
	result, err := c.authenticator.AuthenticateSafeCookie(conn, cookiePath)
	c.lastAuthMu.Lock()
	c.lastAuthResult = result
	c.lastAuthMu.Unlock()

	if err != nil {
		c.setState(StateDisconnected)
		_ = conn.Close()
		return result, err
	}

	// Ensure connection deadline is cleared before launching asynchronous reader loop
	_ = conn.SetDeadline(time.Time{})

	c.setState(StateAuthenticated)

	// Start asynchronous protocol and event demultiplexing loop
	go c.readLoop(conn)

	return result, nil
}

// LastAuthResult returns the result of the most recent authentication attempt.
func (c *Client) LastAuthResult() *AuthResult {
	c.lastAuthMu.RLock()
	defer c.lastAuthMu.RUnlock()
	return c.lastAuthResult
}

// SendCommand sends a command line and awaits the synchronous 250/5xx reply lines.
func (c *Client) SendCommand(ctx context.Context, cmd string) ([]string, error) {
	if c.State() != StateAuthenticated {
		return nil, ErrInvalidState
	}

	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()

	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil {
		return nil, ErrNotConnected
	}

	// Drain any stale reply
	select {
	case <-c.replyChan:
	default:
	}

	// Set write deadline for sending command without interfering with concurrent readLoop
	writeTimeout := c.cfg.Tor.ConnectionTimeout
	if writeTimeout <= 0 {
		writeTimeout = 5 * time.Second
	}
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.SetWriteDeadline(time.Time{})
	}()

	cleanCmd := strings.TrimRight(cmd, "\r\n") + "\r\n"
	if _, err := io.WriteString(conn, cleanCmd); err != nil {
		return nil, fmt.Errorf("failed to write command %q: %w", cmd, err)
	}

	select {
	case lines := <-c.replyChan:
		if len(lines) == 0 {
			return nil, ErrProtocolViolation
		}
		firstLine := lines[0]
		if strings.HasPrefix(firstLine, "5") {
			return lines, fmt.Errorf("tor command error: %s", lines[len(lines)-1])
		}
		return lines, nil

	case <-ctx.Done():
		return nil, ctx.Err()

	case <-time.After(c.cfg.Tor.ConnectionTimeout):
		return nil, ErrCommandTimeout

	case <-c.closeChan:
		return nil, ErrNotConnected
	}
}

// readLoop demultiplexes asynchronous 650 events from synchronous command responses.
func (c *Client) readLoop(conn net.Conn) {
	maxMsgSize := c.cfg.Tor.MaxProtocolMsgSize
	if maxMsgSize <= 0 || maxMsgSize > 65536 {
		maxMsgSize = 65536
	}
	reader := bufio.NewReaderSize(conn, maxMsgSize)
	var currentReplyLines []string
	currentReplyBytes := 0

	for {
		select {
		case <-c.closeChan:
			return
		default:
		}

		line, err := readBoundedLine(reader, maxMsgSize)
		if err != nil {
			select {
			case <-c.closeChan:
				return
			default:
			}
			c.handleDisconnect()
			return
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Asynchronous 650 event notification
		if isAsyncEventLine(line) {
			evt := parseEventLine(line)
			c.dispatchAsyncEvent(evt)
			continue
		}

		// Synchronous command reply lines (e.g. 250-, 250+, 250 OK, 5xx)
		currentReplyBytes += len(line)
		if currentReplyBytes > MaxAggregateResponseBytes {
			if c.logger != nil {
				c.logger.Error(logging.CategoryTor, "readLoop", fmt.Sprintf("aggregate response size %d exceeded maximum limit of %d bytes", currentReplyBytes, MaxAggregateResponseBytes))
			}
			select {
			case c.replyChan <- nil:
			default:
			}
			c.handleDisconnect()
			return
		}

		if len(currentReplyLines) >= MaxResponseLines {
			if c.logger != nil {
				c.logger.Error(logging.CategoryTor, "readLoop", fmt.Sprintf("response line count %d exceeded maximum limit of %d", len(currentReplyLines), MaxResponseLines))
			}
			select {
			case c.replyChan <- nil:
			default:
			}
			c.handleDisconnect()
			return
		}

		currentReplyLines = append(currentReplyLines, line)

		// End of reply condition: line starts with 3 digits followed by a space
		if len(line) >= 4 && line[3] == ' ' {
			select {
			case c.replyChan <- currentReplyLines:
			default:
				// If no waiter, replace stale buffer
				select {
				case <-c.replyChan:
				default:
				}
				c.replyChan <- currentReplyLines
			}
			currentReplyLines = nil
			currentReplyBytes = 0
		}
	}
}

func (c *Client) dispatchAsyncEvent(evt Event) {
	c.monMu.Lock()
	c.totalEvents++
	c.monMu.Unlock()

	c.subMu.RLock()
	defer c.subMu.RUnlock()

	for sub := range c.subscribers {
		select {
		case sub <- evt:
		default:
			// Buffer full: drop event and transition monitoring state to DEGRADED
			c.monMu.Lock()
			c.droppedEvents++
			c.lastDropTime = time.Now().UTC()
			c.isDegraded = true
			c.degradedReason = fmt.Sprintf("event queue overflow: %d events dropped due to buffer saturation", c.droppedEvents)
			c.monMu.Unlock()

			if c.logger != nil {
				c.logger.Warn(logging.CategoryTor, "EventDispatcher", "subscriber queue full: dropped event")
			}
		}
	}
}

// MonitoringStatus returns the current event queue health, drop counts, and degradation status.
func (c *Client) MonitoringStatus() MonitoringStatus {
	c.monMu.RLock()
	defer c.monMu.RUnlock()

	health := MonitoringHealthNormal
	if c.isDegraded {
		health = MonitoringHealthDegraded
	}

	return MonitoringStatus{
		Health:         health,
		DroppedEvents:  c.droppedEvents,
		TotalEvents:    c.totalEvents,
		LastDropTime:   c.lastDropTime,
		DegradedReason: c.degradedReason,
	}
}

// IsMonitoringDegraded reports whether the event stream has experienced buffer overflow.
func (c *Client) IsMonitoringDegraded() bool {
	c.monMu.RLock()
	defer c.monMu.RUnlock()
	return c.isDegraded
}

func (c *Client) handleDisconnect() {
	c.connMu.Lock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	c.connMu.Unlock()

	c.setState(StateDisconnected)
}

// Close gracefully terminates the Tor control connection. It is idempotent.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeChan)

		c.connMu.Lock()
		if c.conn != nil {
			// Best-effort QUIT command
			_ = c.conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = io.WriteString(c.conn, "QUIT\r\n")
			c.closeErr = c.conn.Close()
			c.conn = nil
		}
		c.connMu.Unlock()

		c.setState(StateClosed)
	})
	return c.closeErr
}

// parseEventLine parses a 650 raw notification line into an Event struct.
func parseEventLine(line string) Event {
	trimmed := strings.TrimSpace(line)
	content := strings.TrimPrefix(trimmed, "650 ")
	parts := strings.Fields(content)

	evt := Event{
		Type:      "UNKNOWN",
		Raw:       line,
		Timestamp: time.Now().UTC(),
		Details:   make(map[string]string),
	}

	if len(parts) > 0 {
		evt.Type = strings.ToUpper(parts[0])
	}
	if len(parts) > 1 {
		evt.Severity = parts[1]
	}
	if len(parts) > 2 {
		evt.Action = parts[2]
	}

	for _, p := range parts {
		if strings.Contains(p, "=") {
			kv := strings.SplitN(p, "=", 2)
			evt.Details[kv[0]] = strings.Trim(kv[1], "\"")
		}
	}

	return evt
}
