package tor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/config"
)

func TestValidateCookiePermissions_CurrentOwner(t *testing.T) {
	tempDir := t.TempDir()
	cookiePath := filepath.Join(tempDir, "valid_cookie")

	cookieBytes := make([]byte, CookieSize)
	for i := range cookieBytes {
		cookieBytes[i] = byte(i)
	}

	if err := os.WriteFile(cookiePath, cookieBytes, 0600); err != nil {
		t.Fatalf("failed to create test cookie file: %v", err)
	}

	readData, err := ValidateAndReadCookieFile(cookiePath)
	if err != nil {
		t.Fatalf("expected ValidateAndReadCookieFile to succeed on owned file, got: %v", err)
	}

	if len(readData) != CookieSize {
		t.Errorf("expected %d bytes, got %d", CookieSize, len(readData))
	}
}

func TestValidateCookiePermissions_DirectoryRejected(t *testing.T) {
	tempDir := t.TempDir()
	_, err := ValidateAndReadCookieFile(tempDir)
	if err == nil {
		t.Errorf("expected error when validating directory as cookie file, got nil")
	}
}

func TestValidateCookiePermissions_NonExistentRejected(t *testing.T) {
	_, err := ValidateAndReadCookieFile("non_existent_cookie_file_12345.bin")
	if err == nil {
		t.Errorf("expected error on non-existent cookie file, got nil")
	}
}

func TestValidateAndReadCookieFile_InvalidSizes(t *testing.T) {
	tempDir := t.TempDir()

	// Sub-test 1: 0 bytes
	emptyPath := filepath.Join(tempDir, "empty_cookie")
	if err := os.WriteFile(emptyPath, []byte{}, 0600); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}
	_, err := ValidateAndReadCookieFile(emptyPath)
	if !errors.Is(err, ErrInvalidCookieSize) {
		t.Errorf("expected ErrInvalidCookieSize on empty file, got: %v", err)
	}

	// Sub-test 2: 31 bytes (undersized)
	shortPath := filepath.Join(tempDir, "short_cookie")
	if err := os.WriteFile(shortPath, make([]byte, 31), 0600); err != nil {
		t.Fatalf("failed to write short file: %v", err)
	}
	_, err = ValidateAndReadCookieFile(shortPath)
	if !errors.Is(err, ErrInvalidCookieSize) {
		t.Errorf("expected ErrInvalidCookieSize on 31-byte file, got: %v", err)
	}

	// Sub-test 3: 33 bytes (oversized / trailing data)
	longPath := filepath.Join(tempDir, "long_cookie")
	if err := os.WriteFile(longPath, make([]byte, 33), 0600); err != nil {
		t.Fatalf("failed to write long file: %v", err)
	}
	_, err = ValidateAndReadCookieFile(longPath)
	if !errors.Is(err, ErrInvalidCookieSize) {
		t.Errorf("expected ErrInvalidCookieSize on 33-byte file, got: %v", err)
	}
}

func TestNoSilentDowngradeToNullOrHashedPassword(t *testing.T) {
	mockServer, _, err := NewInMemoryMockTorServer()
	if err != nil {
		t.Fatalf("failed to launch in-memory mock tor server: %v", err)
	}
	defer mockServer.Close()

	testCases := []struct {
		name           string
		advertisedAuth string
	}{
		{"NULL only", "NULL"},
		{"HASHEDPASSWORD only", "HASHEDPASSWORD"},
		{"NULL and HASHEDPASSWORD", "NULL,HASHEDPASSWORD"},
		{"UNKNOWN method", "UNSUPPORTED_METHOD"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer.SetAuthMethods(tc.advertisedAuth)

			cfg := config.DefaultConfig()
			cfg.Tor.Enabled = true
			cfg.Tor.ControlEndpoint = "127.0.0.1:9051"
			cfg.Tor.ConnectionTimeout = 1 * time.Second

			client := mockServer.Client(cfg, nil)
			defer client.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			if err := client.Connect(ctx); err != nil {
				t.Fatalf("client.Connect failed: %v", err)
			}

			authRes, err := client.Authenticate(ctx)
			if err == nil {
				t.Fatalf("expected client.Authenticate to fail and refuse downgrade, but got success: %+v", authRes)
			}

			if !errors.Is(err, ErrAuthFailed) {
				t.Errorf("expected ErrAuthFailed, got: %v", err)
			}

			if authRes == nil || authRes.Success {
				t.Errorf("expected authRes.Success to be false, got: %+v", authRes)
			}

			// Verify client disconnected and did not transition to Authenticated state
			if client.State() == StateAuthenticated {
				t.Errorf("client state transitioned to Authenticated despite unsupported auth methods")
			}
		})
	}
}
