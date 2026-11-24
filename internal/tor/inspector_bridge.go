package tor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxInspectorOutputBytes is the maximum bytes permitted from inspector stdout/stderr (64 KB).
	MaxInspectorOutputBytes = 65536
)

var errInspectorOutputLimit = errors.New("inspector output limit exceeded")

type boundedBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
	onExceed func()
}

func newBoundedBuffer(limit int, onExceed ...func()) *boundedBuffer {
	b := &boundedBuffer{limit: limit}
	if len(onExceed) > 0 {
		b.onExceed = onExceed[0]
	}
	return b
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.exceeded {
		return 0, errInspectorOutputLimit
	}
	remaining := b.limit - b.buf.Len()
	if len(p) > remaining {
		if remaining > 0 {
			_, _ = b.buf.Write(p[:remaining])
		}
		b.exceeded = true
		if b.onExceed != nil {
			b.onExceed()
		}
		return remaining, errInspectorOutputLimit
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

func (b *boundedBuffer) String() string {
	return b.buf.String()
}

// InspectorBridge manages IPC communication with the Rust pg-tor-inspector executable.
type InspectorBridge struct {
	binaryPath string
	timeout    time.Duration
}

// NewInspectorBridge initializes a bridge with the configured binary path and timeout.
func NewInspectorBridge(path string, timeout time.Duration) *InspectorBridge {
	if path == "" {
		path = "pg-tor-inspector"
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &InspectorBridge{
		binaryPath: path,
		timeout:    timeout,
	}
}

// FindBinary attempts to locate the pg-tor-inspector binary following trusted path resolution policy.
// It strictly prevents silent execution of untrusted executables from arbitrary current working directories.
func (b *InspectorBridge) FindBinary() (string, error) {
	// 1. If configured path is explicitly absolute, validate it directly.
	if filepath.IsAbs(b.binaryPath) {
		clean := filepath.Clean(b.binaryPath)
		if fi, err := os.Stat(clean); err == nil && fi.Mode().IsRegular() {
			return clean, nil
		}
		return "", fmt.Errorf("%w: absolute binary path %q does not exist or is not a regular file", ErrInspectorUnavailable, b.binaryPath)
	}

	// Relative paths are rejected. In particular, do not resolve repository build
	// paths from the current working directory: an attacker-controlled CWD could
	// plant a lookalike executable under crates/.../target/.
	if strings.ContainsRune(b.binaryPath, filepath.Separator) || strings.ContainsRune(b.binaryPath, '/') {
		return "", fmt.Errorf("%w: relative binary path %q is untrusted; configure an absolute path", ErrInspectorUnavailable, b.binaryPath)
	}

	// 2. Check companion binary in the same directory as the running gateway executable
	if execPath, err := os.Executable(); err == nil && execPath != "" {
		execDir := filepath.Dir(execPath)
		cand := filepath.Join(execDir, b.binaryPath)
		if fi, err := os.Stat(cand); err == nil && fi.Mode().IsRegular() {
			return cand, nil
		}
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(b.binaryPath), ".exe") {
			candWin := filepath.Join(execDir, b.binaryPath+".exe")
			if fi, err := os.Stat(candWin); err == nil && fi.Mode().IsRegular() {
				return candWin, nil
			}
		}
	}

	// 3. Search system PATH, strictly rejecting current directory lookups (exec.ErrDot)
	binName := b.binaryPath
	if binName == "" {
		binName = "pg-tor-inspector"
	}
	lp, lookErr := exec.LookPath(binName)
	if errors.Is(lookErr, exec.ErrDot) {
		return "", fmt.Errorf("%w: PATH resolution selected the current directory for %q", ErrInspectorUnavailable, binName)
	}
	if lookErr == nil {
		if abs, err := filepath.Abs(lp); err == nil {
			// Reject if resolved binary is inside current working directory.
			if cwd, err := os.Getwd(); err == nil {
				rel, err := filepath.Rel(cwd, abs)
				if err == nil && !strings.HasPrefix(rel, "..") && rel != "." {
					return "", fmt.Errorf("%w: binary resolved to current working directory %q: rejected for security", ErrInspectorUnavailable, abs)
				}
			}
			if fi, err := os.Stat(abs); err == nil && fi.Mode().IsRegular() {
				return abs, nil
			}
		}
	}

	return "", fmt.Errorf("%w: trusted binary %q not found", ErrInspectorUnavailable, b.binaryPath)
}

type inspectorRequest struct {
	Version string `json:"version"`
	Command string `json:"command"`
	Payload string `json:"payload"`
}

type inspectorResponse[T any] struct {
	Version   string `json:"version"`
	Status    string `json:"status"`
	Data      T      `json:"data"`
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message,omitempty"`
}

// executeInspector runs pg-tor-inspector for one command/payload round-trip.
func (b *InspectorBridge) executeInspector(cmdName, payload string) ([]byte, error) {
	if len(payload) > MaxLineLength {
		return nil, fmt.Errorf("%w: payload %d bytes exceeds maximum line length of %d bytes", ErrProtocolViolation, len(payload), MaxLineLength)
	}

	bin, err := b.FindBinary()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()

	req := inspectorRequest{
		Version: "1.0",
		Command: cmdName,
		Payload: payload,
	}
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize inspector request: %w", err)
	}
	reqData = append(reqData, '\n')

	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = bytes.NewReader(reqData)
	stdout := newBoundedBuffer(MaxInspectorOutputBytes, cancel)
	stderr := newBoundedBuffer(MaxInspectorOutputBytes, cancel)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()
	// Check both streams before interpreting the process error: exceeding either
	// bound cancels the child immediately and is always a protocol violation.
	if stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf("%w: pg-tor-inspector stdout/stderr exceeded maximum limit of %d bytes", ErrProtocolViolation, MaxInspectorOutputBytes)
	}
	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("pg-tor-inspector execution timed out after %v", b.timeout)
		}
		return nil, fmt.Errorf("pg-tor-inspector execution failed: %w (stderr: %s)", runErr, stderr.String())
	}

	return stdout.Bytes(), nil
}

// ParseBootstrap invokes pg-tor-inspector to parse bootstrap status, with Go revalidation.
func (b *InspectorBridge) ParseBootstrap(payload string) (*BootstrapStatus, error) {
	rawResp, err := b.executeInspector("parse_bootstrap", payload)
	if err != nil {
		if errors.Is(err, ErrProtocolViolation) {
			return nil, err
		}
		// Fallback to internal Go parser if inspector is unavailable
		return FallbackParseBootstrap(payload)
	}

	var resp inspectorResponse[struct {
		Progress int    `json:"progress"`
		Tag      string `json:"tag"`
		Summary  string `json:"summary"`
		Warning  string `json:"warning"`
		Ready    bool   `json:"ready"`
	}]

	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return FallbackParseBootstrap(payload)
	}

	if resp.Status != "ok" {
		return nil, fmt.Errorf("inspector error %s: %s", resp.ErrorCode, resp.Message)
	}

	// Revalidate in Go (sole authority of state)
	if resp.Data.Progress < 0 || resp.Data.Progress > 100 {
		return nil, fmt.Errorf("inspector returned invalid progress percentage: %d", resp.Data.Progress)
	}

	return &BootstrapStatus{
		Progress: resp.Data.Progress,
		Tag:      resp.Data.Tag,
		Summary:  resp.Data.Summary,
		Warning:  resp.Data.Warning,
		Ready:    resp.Data.Ready,
		Updated:  time.Now().UTC(),
	}, nil
}

// ParseCircuits invokes pg-tor-inspector to parse circuit status, with Go revalidation.
func (b *InspectorBridge) ParseCircuits(payload string) ([]Circuit, error) {
	rawResp, err := b.executeInspector("parse_circuits", payload)
	if err != nil {
		if errors.Is(err, ErrProtocolViolation) {
			return nil, err
		}
		return FallbackParseCircuits(payload)
	}

	type relayDto struct {
		Fingerprint string `json:"fingerprint"`
		Nickname    string `json:"nickname"`
	}
	type circuitDto struct {
		ID         string     `json:"id"`
		Status     string     `json:"status"`
		Path       []relayDto `json:"path"`
		BuildFlags []string   `json:"build_flags"`
		Purpose    string     `json:"purpose"`
	}

	var resp inspectorResponse[[]circuitDto]
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return FallbackParseCircuits(payload)
	}

	if resp.Status != "ok" {
		return nil, fmt.Errorf("inspector error %s: %s", resp.ErrorCode, resp.Message)
	}

	// Revalidate circuits in Go
	var circuits []Circuit
	validStatuses := map[string]bool{
		"LAUNCHED": true, "BUILT": true, "EXTENDED": true, "FAILED": true, "CLOSED": true,
	}

	for _, c := range resp.Data {
		if c.ID == "" {
			continue
		}
		statusUpper := strings.ToUpper(c.Status)
		if !validStatuses[statusUpper] {
			continue
		}

		var path []Relay
		for _, r := range c.Path {
			path = append(path, Relay{
				Fingerprint: r.Fingerprint,
				Nickname:    r.Nickname,
			})
		}

		circuits = append(circuits, Circuit{
			ID:         c.ID,
			Status:     statusUpper,
			Path:       path,
			BuildFlags: c.BuildFlags,
			Purpose:    c.Purpose,
			BuildTime:  time.Now().UTC(),
		})
	}

	return circuits, nil
}

// FallbackParseBootstrap provides an internal Go parser for bootstrap lines.
func FallbackParseBootstrap(payload string) (*BootstrapStatus, error) {
	lines := strings.Split(payload, "\n")
	targetLine := ""
	for _, l := range lines {
		if strings.Contains(l, "BOOTSTRAP") {
			targetLine = l
			break
		}
	}
	if targetLine == "" {
		targetLine = payload
	}

	progress := -1
	tag := "unknown"
	summary := "Unknown"
	warning := ""

	tokens := tokenizeLine(targetLine)
	for k, v := range tokens {
		switch strings.ToUpper(k) {
		case "PROGRESS":
			if p, err := strconv.Atoi(v); err == nil && p >= 0 && p <= 100 {
				progress = p
			}
		case "TAG":
			tag = v
		case "SUMMARY":
			summary = v
		case "WARNING":
			warning = v
		}
	}

	if progress < 0 {
		return nil, fmt.Errorf("%w: missing or invalid PROGRESS in bootstrap string", ErrProtocolViolation)
	}

	return &BootstrapStatus{
		Progress: progress,
		Tag:      tag,
		Summary:  summary,
		Warning:  warning,
		Ready:    progress == 100 && (tag == "done" || tag == ""),
		Updated:  time.Now().UTC(),
	}, nil
}

// FallbackParseCircuits provides an internal Go parser for circuit-status lines.
func FallbackParseCircuits(payload string) ([]Circuit, error) {
	lines := strings.Split(payload, "\n")
	var circuits []Circuit
	validStatuses := map[string]bool{
		"LAUNCHED": true, "BUILT": true, "EXTENDED": true, "FAILED": true, "CLOSED": true,
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "250 OK" || strings.HasPrefix(trimmed, "250+") || trimmed == "." {
			continue
		}

		// Strip leading 250- prefix
		content := trimmed
		if idx := strings.Index(content, "circuit-status="); idx != -1 {
			content = content[idx+len("circuit-status="):]
		} else if strings.HasPrefix(content, "250-") {
			content = strings.TrimPrefix(content, "250-")
		} else if strings.HasPrefix(content, "250 ") {
			content = strings.TrimPrefix(content, "250 ")
		}

		parts := strings.Fields(content)
		if len(parts) < 2 {
			continue
		}

		id := parts[0]
		status := strings.ToUpper(parts[1])
		if !validStatuses[status] {
			continue
		}

		var path []Relay
		var flags []string
		purpose := ""

		for _, p := range parts[2:] {
			if strings.Contains(p, "=") {
				kv := strings.SplitN(p, "=", 2)
				switch strings.ToUpper(kv[0]) {
				case "PURPOSE":
					purpose = kv[1]
				case "BUILD_FLAGS":
					flags = strings.Split(kv[1], ",")
				}
			} else if strings.Contains(p, "$") || strings.Contains(p, "~") {
				for _, rStr := range strings.Split(p, ",") {
					rParts := strings.SplitN(rStr, "~", 2)
					fp := strings.TrimPrefix(rParts[0], "$")
					nick := "Unnamed"
					if len(rParts) > 1 {
						nick = rParts[1]
					}
					path = append(path, Relay{Fingerprint: fp, Nickname: nick})
				}
			}
		}

		circuits = append(circuits, Circuit{
			ID:         id,
			Status:     status,
			Path:       path,
			BuildFlags: flags,
			Purpose:    purpose,
			BuildTime:  time.Now().UTC(),
		})
	}

	return circuits, nil
}

func tokenizeLine(line string) map[string]string {
	tokens := make(map[string]string)
	parts := strings.Fields(line)

	for _, p := range parts {
		if strings.Contains(p, "=") {
			kv := strings.SplitN(p, "=", 2)
			val := strings.Trim(kv[1], "\"")
			tokens[kv[0]] = val
		}
	}
	return tokens
}
