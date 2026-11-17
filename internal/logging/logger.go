package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Level represents log severity.
type Level string

const (
	LevelDebug Level = "DEBUG"
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
	LevelAudit Level = "AUDIT"
)

// LevelSeverity maps level string to numeric rank for threshold comparison.
var levelSeverity = map[Level]int{
	LevelDebug: 10,
	LevelInfo:  20,
	LevelWarn:  30,
	LevelError: 40,
	LevelAudit: 50,
}

// Category represents a logging domain module.
type Category string

const (
	CategorySystem      Category = "System"
	CategoryNetwork     Category = "Network"
	CategoryTor         Category = "Tor"
	CategoryVPN         Category = "VPN"
	CategoryRouting     Category = "Routing"
	CategoryFirewall    Category = "Firewall"
	CategoryTracker     Category = "Tracker"
	CategoryObfuscation Category = "Obfuscation"
	CategorySecurity    Category = "Security"
	CategoryErrors      Category = "Errors"
	CategoryAudit       Category = "Audit"
)

// LogEntry represents a single structured log record.
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"` // Captured in UTC
	Level     Level                  `json:"level"`
	Category  Category               `json:"category"`
	Module    string                 `json:"module"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// LogFilter defines criteria for querying stored or buffered logs.
type LogFilter struct {
	Level    Level
	Category Category
	Module   string
	Query    string
	Since    time.Time
}

// Redactor masks sensitive information from log messages and fields.
type Redactor struct {
	macRegex        *regexp.Regexp
	secretRegex     *regexp.Regexp
	bearerRegex     *regexp.Regexp
	privateKeyRegex *regexp.Regexp
}

// NewRedactor initializes pattern matchers for sensitive data redaction.
func NewRedactor() *Redactor {
	return &Redactor{
		// Matches MAC addresses like 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E
		macRegex: regexp.MustCompile(`(?i)\b([0-9a-f]{2}[:-]){5}([0-9a-f]{2})\b`),
		// Matches key=value or JSON secrets
		secretRegex: regexp.MustCompile(`(?i)\b(password|passwd|secret|token|apikey)\s*[:=]\s*["']?([^\s,"']+)["']?`),
		// Matches Bearer authentication tokens
		bearerRegex: regexp.MustCompile(`(?i)\b(bearer\s+)[a-zA-Z0-9_\-\.]{8,}\b`),
		// Matches PEM encoded private keys
		privateKeyRegex: regexp.MustCompile(`-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[\s\S]+?-----END[ A-Z0-9_-]+PRIVATE KEY-----`),
	}
}

// Redact sanitizes an input string, masking hardware identifiers, keys, and tokens.
func (r *Redactor) Redact(input string) string {
	if r == nil || input == "" {
		return input
	}

	// Redact PEM private keys
	out := r.privateKeyRegex.ReplaceAllString(input, "[REDACTED PRIVATE KEY]")

	// Redact bearer tokens
	out = r.bearerRegex.ReplaceAllString(out, "Bearer [REDACTED]")

	// Redact key-value secrets
	out = r.secretRegex.ReplaceAllString(out, "$1=[REDACTED]")

	// Redact MAC addresses: keep first 2 octets, mask middle, keep last octet
	out = r.macRegex.ReplaceAllStringFunc(out, func(m string) string {
		parts := strings.FieldsFunc(m, func(c rune) bool {
			return c == ':' || c == '-'
		})
		if len(parts) == 6 {
			return fmt.Sprintf("%s:%s:**:**:**:%s", parts[0], parts[1], parts[5])
		}
		return "**:**:**:**:**:**"
	})

	return out
}

// Logger is a thread-safe structured logger with an in-memory buffer, file persistence,
// automated size-based rotation, and safe Recycle Bin archiving and restoration.
type Logger struct {
	mu               sync.RWMutex
	minLevel         Level
	fileWriter       *os.File
	consoleOut       io.Writer
	logFile          string
	logDir           string
	recycleDir       string
	redactor         *Redactor
	redactActive     bool
	buffer           []LogEntry
	maxBuffer        int
	maxFileSizeBytes int64
	currentFileSize  int64
}

// Options configures the logger.
type Options struct {
	MinLevel         Level
	LogDir           string
	Filename         string
	RecycleBinDir    string
	LogToConsole     bool
	LogToFile        bool
	RedactSensitive  bool
	MaxBuffer        int
	MaxFileSizeBytes int64 // Default 10 MB if zero or negative
}

// New creates and initializes a Logger instance.
func New(opts Options) (*Logger, error) {
	if opts.MinLevel == "" {
		opts.MinLevel = LevelInfo
	}
	if opts.MaxBuffer <= 0 {
		opts.MaxBuffer = 1000
	}
	if opts.MaxFileSizeBytes <= 0 {
		opts.MaxFileSizeBytes = 10 * 1024 * 1024 // 10 MB default
	}
	if opts.LogDir == "" {
		opts.LogDir = "Logs"
	}
	if opts.Filename == "" {
		opts.Filename = "privacy-gateway.log"
	}
	if opts.RecycleBinDir == "" {
		opts.RecycleBinDir = "Recycle Bin"
	}

	l := &Logger{
		minLevel:         opts.MinLevel,
		logDir:           opts.LogDir,
		recycleDir:       opts.RecycleBinDir,
		redactActive:     opts.RedactSensitive,
		redactor:         NewRedactor(),
		buffer:           make([]LogEntry, 0, opts.MaxBuffer),
		maxBuffer:        opts.MaxBuffer,
		maxFileSizeBytes: opts.MaxFileSizeBytes,
	}

	if opts.LogToConsole {
		l.consoleOut = os.Stdout
	}

	if opts.LogToFile {
		if err := os.MkdirAll(opts.LogDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create log directory %q: %w", opts.LogDir, err)
		}
		logFilePath := filepath.Join(opts.LogDir, opts.Filename)
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %q: %w", logFilePath, err)
		}

		fi, err := f.Stat()
		if err == nil {
			l.currentFileSize = fi.Size()
		}

		l.fileWriter = f
		l.logFile = logFilePath
	}

	return l, nil
}

// Close closes any open file handles safely.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fileWriter != nil {
		err := l.fileWriter.Close()
		l.fileWriter = nil
		return err
	}
	return nil
}

// Log records a structured entry, executing redaction BEFORE in-memory buffering or disk writing.
func (l *Logger) Log(lvl Level, cat Category, module, msg string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if levelSeverity[lvl] < levelSeverity[l.minLevel] {
		return
	}

	// REDACTION BEFORE BUFFERING:
	// Sensitive information is sanitized immediately prior to inserting into the in-memory buffer
	// or formatting for disk persistence.
	sanitizedMsg := msg
	if l.redactActive && l.redactor != nil {
		sanitizedMsg = l.redactor.Redact(msg)
	}

	sanitizedFields := make(map[string]interface{})
	for k, v := range fields {
		if l.redactActive && l.redactor != nil {
			if strVal, ok := v.(string); ok {
				sanitizedFields[k] = l.redactor.Redact(strVal)
			} else {
				sanitizedFields[k] = v
			}
		} else {
			sanitizedFields[k] = v
		}
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     lvl,
		Category:  cat,
		Module:    module,
		Message:   sanitizedMsg,
		Fields:    sanitizedFields,
	}

	// Append redacted entry to in-memory buffer (ring buffer)
	if len(l.buffer) >= l.maxBuffer {
		l.buffer = l.buffer[1:]
	}
	l.buffer = append(l.buffer, entry)

	line := fmt.Sprintf("[%s] [%-5s] [%-10s] [%-15s] %s\n",
		entry.Timestamp.Format("2006-01-02 15:04:05 UTC"),
		entry.Level,
		entry.Category,
		entry.Module,
		entry.Message,
	)

	if l.consoleOut != nil {
		fmt.Fprint(l.consoleOut, line)
	}

	if l.fileWriter != nil {
		lineLen := int64(len(line))
		// Check if rotation is needed due to file size limit
		if l.currentFileSize+lineLen > l.maxFileSizeBytes && l.maxFileSizeBytes > 0 {
			_ = l.rotateLocked()
		}

		if l.fileWriter != nil {
			n, err := fmt.Fprint(l.fileWriter, line)
			if err == nil {
				l.currentFileSize += int64(n)
			}
		}
	}
}

// Debug logs at DEBUG level.
func (l *Logger) Debug(cat Category, module, msg string) {
	l.Log(LevelDebug, cat, module, msg, nil)
}

// Info logs at INFO level.
func (l *Logger) Info(cat Category, module, msg string) {
	l.Log(LevelInfo, cat, module, msg, nil)
}

// Warn logs at WARN level.
func (l *Logger) Warn(cat Category, module, msg string) {
	l.Log(LevelWarn, cat, module, msg, nil)
}

// Error logs at ERROR level.
func (l *Logger) Error(cat Category, module, msg string) {
	l.Log(LevelError, cat, module, msg, nil)
}

// Audit logs at AUDIT level.
func (l *Logger) Audit(cat Category, module, msg string) {
	l.Log(LevelAudit, cat, module, msg, nil)
}

// Search queries the in-memory log buffer according to the given filter criteria.
func (l *Logger) Search(filter LogFilter) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var results []LogEntry
	for _, entry := range l.buffer {
		if filter.Level != "" && entry.Level != filter.Level {
			continue
		}
		if filter.Category != "" && entry.Category != filter.Category {
			continue
		}
		if filter.Module != "" && !strings.EqualFold(entry.Module, filter.Module) {
			continue
		}
		if !filter.Since.IsZero() && entry.Timestamp.Before(filter.Since) {
			continue
		}
		if filter.Query != "" {
			q := strings.ToLower(filter.Query)
			if !strings.Contains(strings.ToLower(entry.Message), q) &&
				!strings.Contains(strings.ToLower(entry.Module), q) {
				continue
			}
		}
		results = append(results, entry)
	}
	return results
}

// Rotate manually triggers rotation of the active log file into the Recycle Bin.
func (l *Logger) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rotateLocked()
}

// rotateLocked safely moves the current log file to the Recycle Bin and opens a fresh one.
// Caller must hold l.mu Lock.
func (l *Logger) rotateLocked() error {
	if l.logFile == "" {
		return fmt.Errorf("no log file is configured")
	}

	if err := os.MkdirAll(l.recycleDir, 0750); err != nil {
		return fmt.Errorf("failed to create recycle bin directory %q: %w", l.recycleDir, err)
	}

	if l.fileWriter != nil {
		_ = l.fileWriter.Close()
		l.fileWriter = nil
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	baseName := filepath.Base(l.logFile)
	archivedName := fmt.Sprintf("%s-%s.archived", baseName, timestamp)
	destination := filepath.Join(l.recycleDir, archivedName)

	if fi, err := os.Stat(l.logFile); err == nil && fi.Size() > 0 {
		if err := os.Rename(l.logFile, destination); err != nil {
			// If rename fails (e.g. cross-device), attempt copy and remove
			if copyErr := copyFile(l.logFile, destination); copyErr != nil {
				return fmt.Errorf("failed to archive log to recycle bin: %w", copyErr)
			}
			_ = os.Remove(l.logFile)
		}
	}

	// Open a fresh active log file
	f, err := os.OpenFile(l.logFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create fresh log file %q: %w", l.logFile, err)
	}
	l.fileWriter = f
	l.currentFileSize = 0

	return nil
}

// ArchiveCurrentLog safely moves the current log file to the Recycle Bin directory
// and opens a fresh log file. Returns the archived file path.
func (l *Logger) ArchiveCurrentLog() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().UTC().Format("20060102-150405")
	baseName := filepath.Base(l.logFile)
	archivedName := fmt.Sprintf("%s-%s.archived", baseName, timestamp)
	destination := filepath.Join(l.recycleDir, archivedName)

	if err := l.rotateLocked(); err != nil {
		return "", err
	}

	return destination, nil
}

// ListRecycledLogs returns all archived log files safely residing inside the Recycle Bin.
func (l *Logger) ListRecycledLogs() ([]string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	entries, err := os.ReadDir(l.recycleDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read recycle bin %q: %w", l.recycleDir, err)
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".archived") {
			files = append(files, filepath.Join(l.recycleDir, entry.Name()))
		}
	}
	return files, nil
}

// RecoverRecycledLog safely restores an archived log file from the Recycle Bin to targetDir.
// Enforces strict directory containment checks to prevent directory traversal attacks.
func (l *Logger) RecoverRecycledLog(archivedPath, destinationDir string) (string, error) {
	cleanArchived := filepath.Clean(archivedPath)
	cleanRecycle := filepath.Clean(l.recycleDir)

	rel, err := filepath.Rel(cleanRecycle, cleanArchived)
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		return "", fmt.Errorf("security violation: source path %q is outside recycle bin %q", archivedPath, l.recycleDir)
	}

	if _, err := os.Stat(cleanArchived); os.IsNotExist(err) {
		return "", fmt.Errorf("archived log file %q does not exist", cleanArchived)
	}

	if err := os.MkdirAll(destinationDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create destination dir: %w", err)
	}

	baseName := filepath.Base(cleanArchived)
	restoredName := strings.TrimSuffix(baseName, ".archived") + ".restored"
	target := filepath.Join(destinationDir, restoredName)

	if err := copyFile(cleanArchived, target); err != nil {
		return "", fmt.Errorf("failed to restore log file: %w", err)
	}

	return target, nil
}

// PurgeRecycledLogs removes archived logs older than retentionDays from the Recycle Bin.
// It never touches non-archived files or .gitkeep files.
func (l *Logger) PurgeRecycledLogs(retentionDays int) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if retentionDays < 0 {
		return 0, fmt.Errorf("retention days must be non-negative")
	}

	entries, err := os.ReadDir(l.recycleDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read recycle bin: %w", err)
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	purgedCount := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".archived") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().UTC().Before(cutoff) || retentionDays == 0 {
			targetPath := filepath.Join(l.recycleDir, entry.Name())
			if err := os.Remove(targetPath); err == nil {
				purgedCount++
			}
		}
	}

	return purgedCount, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
