package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRedactor(t *testing.T) {
	redactor := NewRedactor()

	// Test MAC address redaction
	input := "Interface eth0 has MAC 00:1A:2B:3C:4D:5E and status UP"
	redacted := redactor.Redact(input)
	if strings.Contains(redacted, "00:1A:2B:3C:4D:5E") {
		t.Fatalf("MAC was not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "00:1A:**:**:**:5E") {
		t.Fatalf("expected masked MAC format, got: %s", redacted)
	}

	// Test token/secret redaction
	secretInput := "Connecting with token: 'secretToken123' and password=myPass"
	redactedSecret := redactor.Redact(secretInput)
	if strings.Contains(redactedSecret, "secretToken123") || strings.Contains(redactedSecret, "myPass") {
		t.Fatalf("secret was not redacted: %s", redactedSecret)
	}

	// Test Bearer token redaction
	bearerInput := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	redactedBearer := redactor.Redact(bearerInput)
	if strings.Contains(redactedBearer, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Fatalf("bearer token was not redacted: %s", redactedBearer)
	}
	if !strings.Contains(redactedBearer, "Bearer [REDACTED]") {
		t.Fatalf("expected Bearer [REDACTED], got: %s", redactedBearer)
	}

	// Test PEM private key redaction
	pemInput := "Cert data: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY----- loaded"
	redactedPem := redactor.Redact(pemInput)
	if strings.Contains(redactedPem, "MIIEowIBAAKCAQEA0") {
		t.Fatalf("private key was not redacted: %s", redactedPem)
	}
	if !strings.Contains(redactedPem, "[REDACTED PRIVATE KEY]") {
		t.Fatalf("expected [REDACTED PRIVATE KEY], got: %s", redactedPem)
	}
}

func TestRedactionBeforeBuffering(t *testing.T) {
	tempDir := t.TempDir()
	logDir := filepath.Join(tempDir, "Logs")
	recycleDir := filepath.Join(tempDir, "Recycle Bin")

	logger, err := New(Options{
		MinLevel:        LevelDebug,
		LogDir:          logDir,
		Filename:        "buffer_test.log",
		RecycleBinDir:   recycleDir,
		LogToConsole:    false,
		LogToFile:       true,
		RedactSensitive: true,
		MaxBuffer:       50,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	// Write sensitive log
	logger.Info(CategorySecurity, "Auth", "User logged in with password=SuperSecretToken and MAC 11:22:33:44:55:66")

	// Query in-memory buffer directly
	entries := logger.Search(LogFilter{Category: CategorySecurity})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry in buffer, got %d", len(entries))
	}

	// Verify redaction was applied BEFORE buffering
	bufMsg := entries[0].Message
	if strings.Contains(bufMsg, "SuperSecretToken") {
		t.Errorf("buffer contains unredacted password secret: %s", bufMsg)
	}
	if strings.Contains(bufMsg, "11:22:33:44:55:66") {
		t.Errorf("buffer contains unredacted MAC address: %s", bufMsg)
	}
	if !strings.Contains(bufMsg, "password=[REDACTED]") {
		t.Errorf("expected redacted password in buffer, got: %s", bufMsg)
	}
}

func TestLogSizeRotation(t *testing.T) {
	tempDir := t.TempDir()
	logDir := filepath.Join(tempDir, "Logs")
	recycleDir := filepath.Join(tempDir, "Recycle Bin")

	// Set small max file size to trigger automatic rotation (e.g. 200 bytes)
	logger, err := New(Options{
		MinLevel:         LevelDebug,
		LogDir:           logDir,
		Filename:         "rotating.log",
		RecycleBinDir:    recycleDir,
		LogToFile:        true,
		RedactSensitive:  false,
		MaxFileSizeBytes: 150,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	// Write lines to exceed 150 bytes and trigger rotation
	for i := 0; i < 5; i++ {
		logger.Info(CategorySystem, "Worker", "A repetitive log message designed to exceed the size limit threshold.")
		time.Sleep(10 * time.Millisecond)
	}

	// Verify at least one archived file exists in Recycle Bin
	recycled, err := logger.ListRecycledLogs()
	if err != nil {
		t.Fatalf("failed to list recycled logs: %v", err)
	}
	if len(recycled) == 0 {
		t.Fatalf("expected rotation to produce archived log in recycle bin, got 0")
	}
}

func TestLogArchivingAndRecovery(t *testing.T) {
	tempDir := t.TempDir()
	logDir := filepath.Join(tempDir, "Logs")
	recycleDir := filepath.Join(tempDir, "Recycle Bin")

	logger, err := New(Options{
		MinLevel:        LevelInfo,
		LogDir:          logDir,
		Filename:        "app.log",
		RecycleBinDir:   recycleDir,
		LogToFile:       true,
		RedactSensitive: false,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	logger.Info(CategoryAudit, "Audit", "Critical security event to be archived")

	// Archive log file
	archivedPath, err := logger.ArchiveCurrentLog()
	if err != nil {
		t.Fatalf("failed to archive log: %v", err)
	}

	if _, err := os.Stat(archivedPath); os.IsNotExist(err) {
		t.Fatalf("archived file does not exist: %s", archivedPath)
	}

	// List recycled logs
	list, err := logger.ListRecycledLogs()
	if err != nil {
		t.Fatalf("failed to list recycled logs: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 archived log file, got %d", len(list))
	}

	// Recover log file safely
	restoreDir := filepath.Join(tempDir, "Restored")
	restored, err := logger.RecoverRecycledLog(list[0], restoreDir)
	if err != nil {
		t.Fatalf("failed to recover recycled log: %v", err)
	}

	if _, err := os.Stat(restored); os.IsNotExist(err) {
		t.Fatalf("restored file does not exist: %s", restored)
	}

	// Test path traversal protection during recovery
	evilPath := filepath.Join(tempDir, "some_file_outside.archived")
	_ = os.WriteFile(evilPath, []byte("outside"), 0600)
	_, err = logger.RecoverRecycledLog(evilPath, restoreDir)
	if err == nil {
		t.Fatalf("expected error for path outside recycle bin, got nil")
	}

	// Test purge
	purged, err := logger.PurgeRecycledLogs(0)
	if err != nil {
		t.Fatalf("failed to purge logs: %v", err)
	}
	if purged != 1 {
		t.Errorf("expected 1 purged file, got %d", purged)
	}
}
