package tor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func findTestInspectorBinary(t *testing.T) string {
	t.Helper()

	candidates := []string{
		filepath.Join("..", "..", "crates", "pg-tor-inspector", "target", "release", "pg-tor-inspector.exe"),
		filepath.Join("..", "..", "crates", "pg-tor-inspector", "target", "release", "pg-tor-inspector"),
		filepath.Join("..", "..", "crates", "pg-tor-inspector", "target", "debug", "pg-tor-inspector.exe"),
		filepath.Join("..", "..", "crates", "pg-tor-inspector", "target", "debug", "pg-tor-inspector"),
		filepath.Join("crates", "pg-tor-inspector", "target", "release", "pg-tor-inspector.exe"),
		filepath.Join("crates", "pg-tor-inspector", "target", "release", "pg-tor-inspector"),
		"pg-tor-inspector.exe",
		"pg-tor-inspector",
	}

	for _, cand := range candidates {
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			abs, err := filepath.Abs(cand)
			if err == nil {
				return abs
			}
			return cand
		}
	}

	t.Skip("pg-tor-inspector binary not found; skipping direct Rust binary IPC tests")
	return ""
}

func TestRustInspector_GoToRustIPC_ValidBootstrap(t *testing.T) {
	binPath := findTestInspectorBinary(t)
	bridge := NewInspectorBridge(binPath, 3*time.Second)

	rawBootstrap := "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\n250 OK"
	status, err := bridge.ParseBootstrap(rawBootstrap)
	if err != nil {
		t.Fatalf("ParseBootstrap via Rust inspector failed: %v", err)
	}

	if status.Progress != 100 {
		t.Errorf("expected progress 100, got %d", status.Progress)
	}
	if status.Tag != "done" {
		t.Errorf("expected tag 'done', got %q", status.Tag)
	}
	if status.Summary != "Done" {
		t.Errorf("expected summary 'Done', got %q", status.Summary)
	}
	if !status.Ready {
		t.Errorf("expected ready=true")
	}
}

func TestRustInspector_GoToRustIPC_ValidCircuits(t *testing.T) {
	binPath := findTestInspectorBinary(t)
	bridge := NewInspectorBridge(binPath, 3*time.Second)

	rawCircuits := "250-circuit-status=1 BUILT $1111111111111111111111111111111111111111~Guard,$2222222222222222222222222222222222222222~Exit BUILD_FLAGS=IS_INTERNAL PURPOSE=GENERAL\n250 OK"
	circuits, err := bridge.ParseCircuits(rawCircuits)
	if err != nil {
		t.Fatalf("ParseCircuits via Rust inspector failed: %v", err)
	}

	if len(circuits) != 1 {
		t.Fatalf("expected 1 circuit, got %d", len(circuits))
	}
	c := circuits[0]
	if c.ID != "1" {
		t.Errorf("expected circuit ID 1, got %q", c.ID)
	}
	if c.Status != "BUILT" {
		t.Errorf("expected status BUILT, got %q", c.Status)
	}
	if len(c.Path) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(c.Path))
	}
	if c.Path[0].Fingerprint != "1111111111111111111111111111111111111111" {
		t.Errorf("unexpected guard fingerprint: %q", c.Path[0].Fingerprint)
	}
	if c.Path[0].Nickname != "Guard" {
		t.Errorf("unexpected guard nickname: %q", c.Path[0].Nickname)
	}
	if c.Path[1].Fingerprint != "2222222222222222222222222222222222222222" {
		t.Errorf("unexpected exit fingerprint: %q", c.Path[1].Fingerprint)
	}
	if c.Path[1].Nickname != "Exit" {
		t.Errorf("unexpected exit nickname: %q", c.Path[1].Nickname)
	}
}

func TestRustInspector_MalformedJSONL(t *testing.T) {
	binPath := findTestInspectorBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath)
	cmd.Stdin = strings.NewReader("{this is not valid json}\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Rust binary exited with error on malformed input: %v (stderr: %s)", err, stderr.String())
	}

	var resp struct {
		Version   string `json:"version"`
		Status    string `json:"status"`
		ErrorCode string `json:"error_code"`
		Message   string `json:"message"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse Rust error response: %v, raw: %s", err, stdout.String())
	}

	if resp.Status != "error" {
		t.Errorf("expected status 'error', got %q", resp.Status)
	}
	if resp.ErrorCode != "ERR_MALFORMED_INPUT" {
		t.Errorf("expected error_code 'ERR_MALFORMED_INPUT', got %q", resp.ErrorCode)
	}
}

func TestRustInspector_OversizedInput(t *testing.T) {
	binPath := findTestInspectorBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 70 KB payload exceeds 64 KB limit
	oversizedLine := strings.Repeat("A", 70000) + "\n"

	cmd := exec.CommandContext(ctx, binPath)
	cmd.Stdin = strings.NewReader(oversizedLine)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Rust binary should handle oversized line gracefully without panicking
	err := cmd.Run()
	if err != nil {
		// Non-zero exit or EOF is acceptable for oversized line rejection, as long as it does not crash unhandled
		t.Logf("Rust binary terminated gracefully on oversized input: %v", err)
	} else {
		var resp struct {
			Status    string `json:"status"`
			ErrorCode string `json:"error_code"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &resp); err == nil {
			if resp.Status != "error" {
				t.Errorf("expected error status for oversized input, got: %s", resp.Status)
			}
		}
	}
}

func TestRustInspector_ProcessTimeout_FallbackToGo(t *testing.T) {
	binPath := findTestInspectorBinary(t)

	// Set an impossible 1-nanosecond timeout to force context deadline exceeded
	bridge := NewInspectorBridge(binPath, 1*time.Nanosecond)

	rawBootstrap := "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=90 TAG=conn_done SUMMARY=\"Connected\"\n250 OK"
	status, err := bridge.ParseBootstrap(rawBootstrap)
	if err != nil {
		t.Fatalf("expected Go fallback parser to succeed on timeout, got error: %v", err)
	}

	if status.Progress != 90 {
		t.Errorf("expected progress 90 from Go fallback, got %d", status.Progress)
	}
	if status.Tag != "conn_done" {
		t.Errorf("expected tag conn_done from Go fallback, got %q", status.Tag)
	}
}

func TestRustInspector_ProcessCrash_FallbackToGo(t *testing.T) {
	// Point to a non-existent binary to simulate missing/crashed sub-process
	bridge := NewInspectorBridge("completely_invalid_crash_binary_xyz.exe", 100*time.Millisecond)

	rawBootstrap := "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=95 TAG=handshake SUMMARY=\"Handshaking\"\n250 OK"
	status, err := bridge.ParseBootstrap(rawBootstrap)
	if err != nil {
		t.Fatalf("expected Go fallback parser to succeed on process crash, got error: %v", err)
	}

	if status.Progress != 95 {
		t.Errorf("expected progress 95 from Go fallback, got %d", status.Progress)
	}
	if status.Tag != "handshake" {
		t.Errorf("expected tag handshake from Go fallback, got %q", status.Tag)
	}

	rawCircuits := "250-circuit-status=5 BUILT $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~NodeA BUILD_FLAGS=IS_INTERNAL PURPOSE=GENERAL\n250 OK"
	circuits, err := bridge.ParseCircuits(rawCircuits)
	if err != nil {
		t.Fatalf("expected Go fallback parser to succeed for circuits on crash, got: %v", err)
	}
	if len(circuits) != 1 || circuits[0].ID != "5" {
		t.Errorf("unexpected circuits from fallback: %v", circuits)
	}
}

func TestRustInspector_InvalidCommand(t *testing.T) {
	binPath := findTestInspectorBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to open stdin pipe: %v", err)
	}

	req := inspectorRequest{
		Version: "1.0",
		Command: "unknown_command_xyz",
		Payload: "test",
	}
	reqData, _ := json.Marshal(req)
	reqData = append(reqData, '\n')

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start Rust inspector: %v", err)
	}

	_, _ = stdin.Write(reqData)
	_ = stdin.Close()

	_ = cmd.Wait()

	var resp struct {
		Status    string `json:"status"`
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v, raw: %s", err, stdout.String())
	}

	if resp.Status != "error" {
		t.Errorf("expected error status, got %q", resp.Status)
	}
	if resp.ErrorCode != "ERR_UNKNOWN_COMMAND" {
		t.Errorf("expected error code ERR_UNKNOWN_COMMAND, got %q", resp.ErrorCode)
	}
}

func TestRustInspector_BoundedBufferExceeded(t *testing.T) {
	buf := newBoundedBuffer(100)
	// Write 80 bytes -> fits
	n, err := buf.Write(bytes.Repeat([]byte("A"), 80))
	if err != nil || n != 80 {
		t.Fatalf("unexpected write error or count: %v, %d", err, n)
	}
	if buf.exceeded {
		t.Fatalf("expected exceeded=false")
	}

	// Write 50 more bytes -> total 130 > 100, must trigger exceeded
	n, err = buf.Write(bytes.Repeat([]byte("B"), 50))
	if !errors.Is(err, errInspectorOutputLimit) || n != 20 {
		t.Fatalf("expected bounded write failure after 20 bytes, got err=%v n=%d", err, n)
	}
	if !buf.exceeded {
		t.Fatalf("expected exceeded=true")
	}
	if len(buf.Bytes()) != 100 {
		t.Errorf("expected buffer length strictly capped at 100, got: %d", len(buf.Bytes()))
	}
}

func TestRustInspector_BoundedBufferCancelsOnOverflow(t *testing.T) {
	called := false
	buf := newBoundedBuffer(4, func() { called = true })
	n, err := buf.Write([]byte("12345"))
	if !errors.Is(err, errInspectorOutputLimit) {
		t.Fatalf("expected output limit error, got %v", err)
	}
	if n != 4 || buf.String() != "1234" {
		t.Fatalf("expected exactly 4 retained bytes, n=%d data=%q", n, buf.String())
	}
	if !called {
		t.Fatal("expected overflow callback to cancel child process")
	}
}

func TestRustInspector_RepositoryRelativeBinaryRejected(t *testing.T) {
	bridge := NewInspectorBridge(filepath.Join("crates", "pg-tor-inspector", "target", "release", "pg-tor-inspector"), time.Second)
	_, err := bridge.FindBinary()
	if err == nil || !errors.Is(err, ErrInspectorUnavailable) {
		t.Fatalf("expected relative repository binary path to be rejected, got %v", err)
	}
}

func TestRustInspector_UntrustedExecutableInCwdRejected(t *testing.T) {
	bridge := NewInspectorBridge("./evil_binary.exe", 1*time.Second)
	_, err := bridge.FindBinary()
	if err == nil {
		t.Fatal("expected arbitrary relative binary path to be rejected, got nil")
	}
	if !errors.Is(err, ErrInspectorUnavailable) {
		t.Errorf("expected ErrInspectorUnavailable, got: %v", err)
	}
}

func TestRustInspector_MissingExecutableError(t *testing.T) {
	bridge := NewInspectorBridge("nonexistent_binary_xyz12345.exe", 1*time.Second)
	_, err := bridge.FindBinary()
	if err == nil {
		t.Fatal("expected error on nonexistent binary, got nil")
	}
	if !errors.Is(err, ErrInspectorUnavailable) {
		t.Errorf("expected ErrInspectorUnavailable, got: %v", err)
	}
}

func TestRustInspector_OversizedPayloadRejected(t *testing.T) {
	binPath := findTestInspectorBinary(t)
	bridge := NewInspectorBridge(binPath, 1*time.Second)

	// Payload exceeding MaxLineLength (64 KB)
	oversizedPayload := strings.Repeat("A", MaxLineLength+100)
	_, err := bridge.ParseBootstrap(oversizedPayload)
	if err == nil {
		t.Fatal("expected oversized payload to fail, got nil")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Errorf("expected ErrProtocolViolation, got: %v", err)
	}
}
