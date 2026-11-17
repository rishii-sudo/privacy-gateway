package monitor

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
)

// SystemInfo encapsulates static and runtime properties of the host environment.
type SystemInfo struct {
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	GoVersion string    `json:"go_version"`
	NumCPU    int       `json:"num_cpu"`
	Hostname  string    `json:"hostname"`
	ProcessID int       `json:"process_id"`
	Timestamp time.Time `json:"timestamp"` // Captured in UTC
}

// SystemHealth captures real-time health metrics of the running application and system.
type SystemHealth struct {
	Status           string    `json:"status"` // "Healthy", "Warning", "Critical"
	MemoryAllocated  uint64    `json:"memory_allocated_bytes"`
	MemoryTotalAlloc uint64    `json:"memory_total_alloc_bytes"`
	MemorySys        uint64    `json:"memory_sys_bytes"`
	NumGC            uint32    `json:"num_gc"`
	Goroutines       int       `json:"goroutines"`
	ActiveInterfaces int       `json:"active_interfaces"`
	Timestamp        time.Time `json:"timestamp"` // Captured in UTC
}

// SystemMonitor provides read-only discovery of host and runtime characteristics.
type SystemMonitor struct {
	readOnly bool
}

// New creates a new read-only SystemMonitor instance.
func New() *SystemMonitor {
	return &SystemMonitor{
		readOnly: true,
	}
}

// GetSystemInfo discovers host environment information.
// All discoveries are strictly read-only.
func (m *SystemMonitor) GetSystemInfo() (SystemInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return SystemInfo{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		NumCPU:    runtime.NumCPU(),
		Hostname:  hostname,
		ProcessID: os.Getpid(),
		Timestamp: time.Now().UTC(),
	}, nil
}

// GetSystemHealth samples current runtime metrics and active network interfaces.
func (m *SystemMonitor) GetSystemHealth() (SystemHealth, error) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	// Read-only discovery of network interfaces
	ifaces, err := net.Interfaces()
	activeCount := 0
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
				activeCount++
			}
		}
	}

	status := "Healthy"
	// Alert if excessive system memory is consumed (> 2 GB)
	if mem.Sys > 2*1024*1024*1024 {
		status = "Warning"
	}

	return SystemHealth{
		Status:           status,
		MemoryAllocated:  mem.Alloc,
		MemoryTotalAlloc: mem.TotalAlloc,
		MemorySys:        mem.Sys,
		NumGC:            mem.NumGC,
		Goroutines:       runtime.NumGoroutine(),
		ActiveInterfaces: activeCount,
		Timestamp:        time.Now().UTC(),
	}, nil
}

// FormatUptime returns a human-readable duration string since start.
func FormatUptime(start time.Time) string {
	d := time.Since(start).Round(time.Second)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
