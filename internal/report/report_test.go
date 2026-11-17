package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/48sh1xbh/privacy-gateway/internal/monitor"
	"github.com/48sh1xbh/privacy-gateway/internal/privacy"
)

func TestAuditReportGeneration(t *testing.T) {
	sysInfo := monitor.SystemInfo{
		OS:        "linux",
		Arch:      "amd64",
		NumCPU:    4,
		Timestamp: time.Now().UTC(),
	}
	sysHealth := monitor.SystemHealth{
		Status:           "Healthy",
		ActiveInterfaces: 2,
		Timestamp:        time.Now().UTC(),
	}

	checks := []privacy.CheckResult{
		privacy.NewCheckResult("SYS_1", "Interface Check", privacy.CategorySystem, privacy.StatusPass, "Interfaces OK"),
		privacy.NewCheckResult("SYS_2", "Hostname Check", privacy.CategorySystem, privacy.StatusFail, "Hostname leaked").
			WithRemediation("Change hostname"),
		privacy.NewCheckResult("TOR_1", "Tor Bootstrap", privacy.CategoryTor, privacy.StatusNotImplemented, "Tor in M2"),
	}

	rep := NewAuditReport(sysInfo, sysHealth, checks)

	if rep.OverallStatus != privacy.StatusFail {
		t.Errorf("expected overall status FAIL, got %s", rep.OverallStatus)
	}
	if rep.Summary.Total != 3 {
		t.Errorf("expected total 3, got %d", rep.Summary.Total)
	}
	if rep.Summary.Pass != 1 || rep.Summary.Fail != 1 || rep.Summary.NotImplemented != 1 {
		t.Errorf("unexpected counts: %+v", rep.Summary)
	}
	if len(rep.Remediations) != 1 {
		t.Fatalf("expected 1 remediation, got %d", len(rep.Remediations))
	}

	// Verify terminal formatting
	termOut := FormatTerminal(rep)
	if !strings.Contains(termOut, "Developed by 48sh1xbh") {
		t.Errorf("developer attribution missing in terminal report")
	}
	if !strings.Contains(termOut, "DISCLAIMER") {
		t.Errorf("disclaimer missing in terminal report")
	}
	if !strings.Contains(termOut, "[ FAIL          ]") {
		t.Errorf("FAIL badge missing in terminal report")
	}

	// Verify JSON export
	jsonData, err := rep.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize JSON: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON report: %v", err)
	}
	if parsed["developer"] != "Developed by 48sh1xbh" {
		t.Errorf("JSON developer field incorrect: %v", parsed["developer"])
	}

	// Test saving report
	tempDir := t.TempDir()
	savedPath, err := rep.SaveJSON(tempDir)
	if err != nil {
		t.Fatalf("failed to save report JSON: %v", err)
	}
	if _, err := os.Stat(savedPath); os.IsNotExist(err) {
		t.Fatalf("saved file does not exist: %s", savedPath)
	}
	if filepath.Ext(savedPath) != ".json" {
		t.Errorf("expected .json extension, got %s", filepath.Ext(savedPath))
	}
}
