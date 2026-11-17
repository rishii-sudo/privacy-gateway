package monitor

import (
	"os"
	"runtime"
	"testing"
	"time"
)

func TestGetSystemInfo(t *testing.T) {
	mon := New()
	info, err := mon.GetSystemInfo()
	if err != nil {
		t.Fatalf("unexpected error getting system info: %v", err)
	}

	if info.OS != runtime.GOOS {
		t.Errorf("expected OS %s, got %s", runtime.GOOS, info.OS)
	}
	if info.Arch != runtime.GOARCH {
		t.Errorf("expected Arch %s, got %s", runtime.GOARCH, info.Arch)
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("expected GoVersion %s, got %s", runtime.Version(), info.GoVersion)
	}
	if info.NumCPU <= 0 {
		t.Errorf("expected NumCPU > 0, got %d", info.NumCPU)
	}
	if info.ProcessID != os.Getpid() {
		t.Errorf("expected PID %d, got %d", os.Getpid(), info.ProcessID)
	}
	if info.Timestamp.Location() != time.UTC {
		t.Errorf("expected timestamp in UTC location, got %v", info.Timestamp.Location())
	}
}

func TestGetSystemHealth(t *testing.T) {
	mon := New()
	health, err := mon.GetSystemHealth()
	if err != nil {
		t.Fatalf("unexpected error getting system health: %v", err)
	}

	if health.Status != "Healthy" && health.Status != "Warning" {
		t.Errorf("unexpected health status: %s", health.Status)
	}
	if health.Goroutines <= 0 {
		t.Errorf("expected Goroutines > 0, got %d", health.Goroutines)
	}
	if health.Timestamp.Location() != time.UTC {
		t.Errorf("expected timestamp in UTC, got %v", health.Timestamp.Location())
	}
}

func TestFormatUptime(t *testing.T) {
	past := time.Now().Add(-1*time.Hour - 30*time.Minute - 15*time.Second)
	uptime := FormatUptime(past)
	if uptime == "" {
		t.Fatalf("expected formatted uptime, got empty string")
	}
}
