package tor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// CookieSize is the exact length in bytes required for Tor SAFECOOKIE authentication.
	CookieSize = 32

	// NonceSize is the length of cryptographic client and server nonces.
	NonceSize = 32

	// ServerHashKey is the HMAC key defined in Tor Control Protocol Spec Section 3.5.
	ServerHashKey = "Tor safe cookie authentication server-to-controller hash"

	// ClientHashKey is the HMAC key defined in Tor Control Protocol Spec Section 3.5.
	ClientHashKey = "Tor safe cookie authentication controller-to-server hash"
)

// Authenticator handles protocol negotiation and SAFECOOKIE challenge-response.
type Authenticator struct {
	readTimeout time.Duration
}

// NewAuthenticator creates an Authenticator with the given I/O deadline.
func NewAuthenticator(timeout time.Duration) *Authenticator {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Authenticator{readTimeout: timeout}
}

// NegotiateProtocol issues PROTOCOLINFO 1 and parses advertised auth methods and cookie path.
func (a *Authenticator) NegotiateProtocol(conn net.Conn) (*ProtocolInfo, error) {
	if err := conn.SetDeadline(time.Now().Add(a.readTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	if _, err := io.WriteString(conn, "PROTOCOLINFO 1\r\n"); err != nil {
		return nil, fmt.Errorf("failed to write PROTOCOLINFO: %w", err)
	}

	lines, err := readMultilineResponse(conn, a.readTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to read PROTOCOLINFO reply: %w", err)
	}

	info := &ProtocolInfo{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "250-AUTH METHODS=") || strings.HasPrefix(trimmed, "250 AUTH METHODS=") {
			// Extract METHODS and COOKIEFILE
			parts := strings.Split(trimmed, " ")
			for _, p := range parts {
				if strings.HasPrefix(p, "METHODS=") {
					methodsStr := strings.TrimPrefix(p, "METHODS=")
					info.AuthMethods = strings.Split(methodsStr, ",")
				} else if strings.HasPrefix(p, "COOKIEFILE=\"") {
					cookieStr := strings.TrimPrefix(p, "COOKIEFILE=\"")
					cookieStr = strings.TrimSuffix(cookieStr, "\"")
					info.CookieFile = cookieStr
				} else if strings.HasPrefix(p, "COOKIEFILE=") {
					info.CookieFile = strings.TrimPrefix(p, "COOKIEFILE=")
				}
			}
		} else if strings.HasPrefix(trimmed, "250-Tor ") || strings.HasPrefix(trimmed, "250 Tor ") {
			info.TorVersion = trimmed
		}
	}

	if len(info.AuthMethods) == 0 {
		return nil, fmt.Errorf("%w: no authentication methods advertised by Tor daemon", ErrProtocolViolation)
	}

	return info, nil
}

// AuthenticateSafeCookie performs the full SAFECOOKIE handshake according to Tor spec Section 3.5.
func (a *Authenticator) AuthenticateSafeCookie(conn net.Conn, cookiePath string) (*AuthResult, error) {
	result := &AuthResult{
		Method:   "SAFECOOKIE",
		Endpoint: conn.RemoteAddr().String(),
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	// 1. Validate cookie file strictly
	cookieBytes, err := ValidateAndReadCookieFile(cookiePath)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	// Best-effort clearing of cookie memory when done
	defer func() {
		for i := range cookieBytes {
			cookieBytes[i] = 0
		}
	}()

	// 2. Generate 32-byte cryptographically secure client nonce
	clientNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, clientNonce); err != nil {
		result.Error = "failed to generate cryptographic client nonce: " + err.Error()
		return result, fmt.Errorf("failed to generate client nonce: %w", err)
	}
	defer func() {
		for i := range clientNonce {
			clientNonce[i] = 0
		}
	}()

	clientNonceHex := hex.EncodeToString(clientNonce)

	// 3. Send AUTHCHALLENGE SAFECOOKIE <ClientNonceHex>
	if err := conn.SetDeadline(time.Now().Add(a.readTimeout)); err != nil {
		return result, err
	}
	challengeCmd := fmt.Sprintf("AUTHCHALLENGE SAFECOOKIE %s\r\n", clientNonceHex)
	if _, err := io.WriteString(conn, challengeCmd); err != nil {
		result.Error = "failed to write AUTHCHALLENGE: " + err.Error()
		return result, fmt.Errorf("failed to write AUTHCHALLENGE: %w", err)
	}

	challengeReply, err := readSingleLineResponse(conn, a.readTimeout)
	if err != nil {
		result.Error = "failed to read AUTHCHALLENGE response: " + err.Error()
		return result, fmt.Errorf("failed to read AUTHCHALLENGE response: %w", err)
	}

	// 4. Parse SERVERHASH and SERVERNONCE
	serverHash, serverNonce, err := parseAuthChallengeReply(challengeReply)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer func() {
		for i := range serverHash {
			serverHash[i] = 0
		}
		for i := range serverNonce {
			serverNonce[i] = 0
		}
	}()

	// 5. Verify server HMAC using constant-time comparison
	serverKey := []byte(ServerHashKey)
	expectedServerHash := computeHMAC(serverKey, cookieBytes, clientNonce, serverNonce)
	defer func() {
		for i := range expectedServerHash {
			expectedServerHash[i] = 0
		}
	}()

	if subtle.ConstantTimeCompare(serverHash, expectedServerHash) != 1 {
		result.Error = "server HMAC validation failed: challenge response rejected"
		return result, ErrInvalidHMAC
	}

	// 6. Compute controller authentication HMAC
	clientKey := []byte(ClientHashKey)
	clientHash := computeHMAC(clientKey, cookieBytes, clientNonce, serverNonce)
	defer func() {
		for i := range clientHash {
			clientHash[i] = 0
		}
	}()

	clientHashHex := hex.EncodeToString(clientHash)

	// 7. Send AUTHENTICATE <ClientHashHex>
	if err := conn.SetDeadline(time.Now().Add(a.readTimeout)); err != nil {
		return result, err
	}
	authCmd := fmt.Sprintf("AUTHENTICATE %s\r\n", clientHashHex)
	if _, err := io.WriteString(conn, authCmd); err != nil {
		result.Error = "failed to write AUTHENTICATE: " + err.Error()
		return result, fmt.Errorf("failed to write AUTHENTICATE: %w", err)
	}

	authReply, err := readSingleLineResponse(conn, a.readTimeout)
	if err != nil {
		result.Error = "failed to read AUTHENTICATE response: " + err.Error()
		return result, fmt.Errorf("failed to read AUTHENTICATE response: %w", err)
	}

	if !strings.HasPrefix(authReply, "250") {
		result.Error = fmt.Sprintf("authentication rejected by daemon: %s", authReply)
		return result, fmt.Errorf("%w: %s", ErrAuthFailed, authReply)
	}

	result.Success = true
	return result, nil
}

// ValidateAndReadCookieFile performs strict file validation and reads exactly 32 bytes from the validated handle.
// This function operates directly on the opened file descriptor to prevent TOCTOU symlink/file replacement.
func ValidateAndReadCookieFile(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("cookie file path is empty")
	}

	cleanPath := filepath.Clean(path)

	// Open the file object directly (using O_NOFOLLOW on Unix to reject symlinks at open-time)
	file, err := openCookieFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cookie file %q: %w", cleanPath, err)
	}
	defer file.Close()

	// Query file metadata directly from the open descriptor/handle (fstat)
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect open cookie file %q: %w", cleanPath, err)
	}

	// Strictly reject symlinks (additional mode check)
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("cookie file %q is a symlink: rejected for security", cleanPath)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("cookie file %q is not a regular file", cleanPath)
	}

	if info.Size() != CookieSize {
		return nil, fmt.Errorf("%w: file size is %d bytes, expected %d", ErrInvalidCookieSize, info.Size(), CookieSize)
	}

	// Validate platform-specific permissions and ownership directly on the opened file handle
	if err := validateCookiePermissions(file, cleanPath, info); err != nil {
		return nil, err
	}

	// Read exactly CookieSize bytes directly from the validated file object
	data := make([]byte, CookieSize)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("failed to read %d bytes from cookie file %q: %w", CookieSize, cleanPath, err)
	}

	// Verify no trailing data exists past CookieSize
	var extra [1]byte
	if n, _ := file.Read(extra[:]); n > 0 {
		return nil, fmt.Errorf("%w: cookie file %q contains trailing data", ErrInvalidCookieSize, cleanPath)
	}

	return data, nil
}

// computeHMAC calculates HMAC-SHA256(key, cookie || clientNonce || serverNonce).
func computeHMAC(key, cookie, clientNonce, serverNonce []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(cookie)
	mac.Write(clientNonce)
	mac.Write(serverNonce)
	return mac.Sum(nil)
}

// parseAuthChallengeReply extracts and hex-decodes SERVERHASH and SERVERNONCE from 250 AUTHCHALLENGE line.
func parseAuthChallengeReply(line string) ([]byte, []byte, error) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "250") {
		return nil, nil, fmt.Errorf("%w: %s", ErrAuthFailed, trimmed)
	}

	tokens := strings.Split(trimmed, " ")
	var serverHashHex, serverNonceHex string

	for _, token := range tokens {
		if strings.HasPrefix(token, "SERVERHASH=") {
			serverHashHex = strings.TrimPrefix(token, "SERVERHASH=")
		} else if strings.HasPrefix(token, "SERVERNONCE=") {
			serverNonceHex = strings.TrimPrefix(token, "SERVERNONCE=")
		}
	}

	if serverHashHex == "" || serverNonceHex == "" {
		return nil, nil, fmt.Errorf("%w: missing SERVERHASH or SERVERNONCE in challenge reply", ErrProtocolViolation)
	}

	serverHash, err := hex.DecodeString(serverHashHex)
	if err != nil || len(serverHash) != sha256.Size {
		return nil, nil, fmt.Errorf("%w: invalid SERVERHASH hex or length (%d)", ErrProtocolViolation, len(serverHash))
	}

	serverNonce, err := hex.DecodeString(serverNonceHex)
	if err != nil || len(serverNonce) != NonceSize {
		return nil, nil, fmt.Errorf("%w: invalid SERVERNONCE hex or length (%d)", ErrProtocolViolation, len(serverNonce))
	}

	return serverHash, serverNonce, nil
}
