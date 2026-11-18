package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/monitor"
	"github.com/rishii-sudo/privacy-gateway/internal/privacy"
)

const (
	// MandatoryAnonymityDisclaimer is required on all user-facing reports.
	MandatoryAnonymityDisclaimer = "DISCLAIMER: Privacy Gateway provides verification, monitoring, and defensive controls. " +
		"No software tool can guarantee absolute anonymity or immunity from network surveillance or advanced traffic analysis. " +
		"Use responsibly and in accordance with applicable laws and policies."

	DeveloperAttribution = "Developed by 48sh1xbh"
)

// SummaryCounts breaks down check results by status.
type SummaryCounts struct {
	Total          int `json:"total"`
	Pass           int `json:"pass"`
	Fail           int `json:"fail"`
	Inconclusive   int `json:"inconclusive"`
	NotImplemented int `json:"not_implemented"`
}

// AuditReport models a complete security and privacy audit snapshot.
type AuditReport struct {
	ReportID      string                `json:"report_id"`
	GeneratedAt   time.Time             `json:"generated_at"` // Captured in UTC
	Developer     string                `json:"developer"`
	Disclaimer    string                `json:"disclaimer"`
	OverallStatus privacy.Status        `json:"overall_status"`
	SystemInfo    monitor.SystemInfo    `json:"system_info"`
	SystemHealth  monitor.SystemHealth  `json:"system_health"`
	Summary       SummaryCounts         `json:"summary"`
	Checks        []privacy.CheckResult `json:"checks"`
	Remediations  []string              `json:"remediations,omitempty"`
}

// NewAuditReport compiles check results and system diagnostics into an AuditReport.
func NewAuditReport(sysInfo monitor.SystemInfo, sysHealth monitor.SystemHealth, checks []privacy.CheckResult) AuditReport {
	now := time.Now().UTC()
	reportID := fmt.Sprintf("PG-AUDIT-%s", now.Format("20060102-150405"))

	counts := SummaryCounts{Total: len(checks)}
	var remediations []string

	for _, c := range checks {
		switch c.Status {
		case privacy.StatusPass:
			counts.Pass++
		case privacy.StatusFail:
			counts.Fail++
			if c.Remediation != "" {
				remediations = append(remediations, fmt.Sprintf("[%s] %s", c.ID, c.Remediation))
			}
		case privacy.StatusInconclusive:
			counts.Inconclusive++
			if c.Remediation != "" {
				remediations = append(remediations, fmt.Sprintf("[%s] %s", c.ID, c.Remediation))
			}
		case privacy.StatusNotImplemented:
			counts.NotImplemented++
		}
	}

	return AuditReport{
		ReportID:      reportID,
		GeneratedAt:   now,
		Developer:     DeveloperAttribution,
		Disclaimer:    MandatoryAnonymityDisclaimer,
		OverallStatus: privacy.AggregateStatus(checks),
		SystemInfo:    sysInfo,
		SystemHealth:  sysHealth,
		Summary:       counts,
		Checks:        checks,
		Remediations:  remediations,
	}
}

// FormatTerminal generates a clean, professional ASCII terminal report.
func FormatTerminal(rep AuditReport) string {
	var b strings.Builder

	border := strings.Repeat("═", 78)
	divider := strings.Repeat("─", 78)

	b.WriteString("\n" + border + "\n")
	b.WriteString("  PRIVACY GATEWAY — SECURITY & PRIVACY AUDIT REPORT\n")
	b.WriteString("  " + rep.Developer + "\n")
	b.WriteString(border + "\n")

	b.WriteString(fmt.Sprintf("  Report ID:       %s\n", rep.ReportID))
	b.WriteString(fmt.Sprintf("  Execution Time:  %s\n", rep.GeneratedAt.Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf("  Host Platform:   %s (%s, %d CPU cores)\n", rep.SystemInfo.OS, rep.SystemInfo.Arch, rep.SystemInfo.NumCPU))
	b.WriteString(fmt.Sprintf("  Active Ifaces:   %d interfaces\n", rep.SystemHealth.ActiveInterfaces))
	b.WriteString(fmt.Sprintf("  Overall Status:  [%s]\n", rep.OverallStatus))
	b.WriteString(divider + "\n")

	b.WriteString(fmt.Sprintf("  SUMMARY: Total: %d | PASS: %d | FAIL: %d | INCONCLUSIVE: %d | NOT_IMPLEMENTED: %d\n",
		rep.Summary.Total, rep.Summary.Pass, rep.Summary.Fail, rep.Summary.Inconclusive, rep.Summary.NotImplemented))
	b.WriteString(divider + "\n")

	// Group checks by category
	categories := []privacy.Category{
		privacy.CategorySystem,
		privacy.CategoryNetwork,
		privacy.CategoryTor,
		privacy.CategoryVPN,
		privacy.CategoryRouting,
		privacy.CategoryFirewall,
		privacy.CategoryTracker,
		privacy.CategoryObfuscation,
		privacy.CategoryIsolation,
		privacy.CategoryDeception,
	}

	for _, cat := range categories {
		var catChecks []privacy.CheckResult
		for _, c := range rep.Checks {
			if c.Category == cat {
				catChecks = append(catChecks, c)
			}
		}

		if len(catChecks) == 0 {
			continue
		}

		b.WriteString(fmt.Sprintf("\n  [%s Checks]\n", cat))
		for _, c := range catChecks {
			badge := formatBadge(c.Status)
			b.WriteString(fmt.Sprintf("  %-17s %-28s %s\n", badge, c.Name, c.ID))
			b.WriteString(fmt.Sprintf("    Summary: %s\n", c.Summary))
			if c.Remediation != "" && (c.Status == privacy.StatusFail || c.Status == privacy.StatusInconclusive) {
				b.WriteString(fmt.Sprintf("    Remediation: %s\n", c.Remediation))
			}
		}
	}

	if len(rep.Remediations) > 0 {
		b.WriteString("\n" + divider + "\n")
		b.WriteString("  RECOMMENDED REMEDIATION ACTIONS:\n")
		for i, rem := range rep.Remediations {
			b.WriteString(fmt.Sprintf("  %2d. %s\n", i+1, rem))
		}
	}

	b.WriteString("\n" + divider + "\n")
	b.WriteString("  " + rep.Disclaimer + "\n")
	b.WriteString(border + "\n\n")

	return b.String()
}

// ToJSON serializes the audit report to formatted JSON bytes.
func (r *AuditReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// SaveJSON writes the JSON representation of the report to the target directory.
func (r *AuditReport) SaveJSON(dir string) (string, error) {
	if dir == "" {
		dir = "Reports"
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("failed to create report directory %q: %w", dir, err)
	}

	fileName := fmt.Sprintf("%s.json", r.ReportID)
	fullPath := filepath.Join(dir, fileName)

	data, err := r.ToJSON()
	if err != nil {
		return "", fmt.Errorf("failed to marshal report JSON: %w", err)
	}

	if err := os.WriteFile(fullPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write report file %q: %w", fullPath, err)
	}

	return fullPath, nil
}

func formatBadge(st privacy.Status) string {
	switch st {
	case privacy.StatusPass:
		return "[ PASS          ]"
	case privacy.StatusFail:
		return "[ FAIL          ]"
	case privacy.StatusInconclusive:
		return "[ INCONCLUSIVE  ]"
	case privacy.StatusNotImplemented:
		return "[ NOT_IMPL      ]"
	default:
		return fmt.Sprintf("[ %-13s ]", string(st))
	}
}
