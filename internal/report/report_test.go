package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rishii-sudo/privacy-gateway/internal/monitor"
	"github.com/rishii-sudo/privacy-gateway/internal/privacy"
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

// findProhibitedIdentityKeyPaths recursively inspects an unmarshaled JSON structure
// (map[string]any or []any) and returns the full JSON paths of any prohibited
// identity fields (such as "current_user" or "username") discovered.
func findProhibitedIdentityKeyPaths(node any, prohibitedKeys []string, path string) []string {
	var violations []string
	switch val := node.(type) {
	case map[string]any:
		for k, v := range val {
			currentPath := k
			if path != "" {
				currentPath = path + "." + k
			}
			lowerK := strings.ToLower(k)
			for _, prohibited := range prohibitedKeys {
				if lowerK == strings.ToLower(prohibited) {
					violations = append(violations, currentPath)
				}
			}
			violations = append(violations, findProhibitedIdentityKeyPaths(v, prohibitedKeys, currentPath)...)
		}
	case []any:
		for i, item := range val {
			currentPath := fmt.Sprintf("%s[%d]", path, i)
			violations = append(violations, findProhibitedIdentityKeyPaths(item, prohibitedKeys, currentPath)...)
		}
	}
	return violations
}

// assertNoProhibitedIdentityKeys recursively validates an unmarshaled JSON structure
// using findProhibitedIdentityKeyPaths, failing the test if any prohibited field is found.
func assertNoProhibitedIdentityKeys(t *testing.T, node any, prohibitedKeys []string) {
	t.Helper()
	violations := findProhibitedIdentityKeyPaths(node, prohibitedKeys, "")
	for _, v := range violations {
		t.Errorf("prohibited identity field detected at JSON path: %s", v)
	}
}

func TestReportDoesNotContainCurrentOSUsername(t *testing.T) {
	prohibitedKeys := []string{"current_user", "username", "user_name", "os_user", "current_username"}

	t.Run("LiveReportStructuralValidation", func(t *testing.T) {
		// 1. Generate live baseline checks and system metrics
		checker := privacy.NewChecker(nil)
		checks, err := checker.RunAllBaselineChecks()
		if err != nil {
			t.Fatalf("RunAllBaselineChecks failed: %v", err)
		}

		sysMon := monitor.New()
		sysInfo, err := sysMon.GetSystemInfo()
		if err != nil {
			t.Fatalf("GetSystemInfo failed: %v", err)
		}
		sysHealth, err := sysMon.GetSystemHealth()
		if err != nil {
			t.Fatalf("GetSystemHealth failed: %v", err)
		}

		liveRep := NewAuditReport(sysInfo, sysHealth, checks)

		// 2. Structural validation of the in-memory Go struct
		foundHostnameCheck := false
		for _, c := range liveRep.Checks {
			if c.ID == "SYS_HOSTNAME_DISCOVERY" {
				foundHostnameCheck = true
				// Prohibited identity fields must not exist
				if _, exists := c.Details["current_user"]; exists {
					t.Errorf("SYS_HOSTNAME_DISCOVERY details must not contain 'current_user'")
				}
				// Details must contain ONLY hostname
				if len(c.Details) != 1 {
					t.Errorf("SYS_HOSTNAME_DISCOVERY details must contain exactly 1 key (hostname), got %d keys: %v", len(c.Details), c.Details)
				}
				if host, exists := c.Details["hostname"]; !exists || host == "" {
					t.Errorf("SYS_HOSTNAME_DISCOVERY details must retain non-empty 'hostname'")
				}
			}
			// Verify no check details contain prohibited identity keys
			for k := range c.Details {
				lowerK := strings.ToLower(k)
				for _, prohibited := range prohibitedKeys {
					if lowerK == strings.ToLower(prohibited) {
						t.Errorf("Check %s details contained prohibited key %q", c.ID, k)
					}
				}
			}
		}
		if !foundHostnameCheck {
			t.Fatalf("expected SYS_HOSTNAME_DISCOVERY check in baseline checks")
		}

		// 3. Structural validation of the serialized JSON report
		jsonData, err := liveRep.ToJSON()
		if err != nil {
			t.Fatalf("ToJSON failed: %v", err)
		}

		var parsedJSON map[string]any
		if err := json.Unmarshal(jsonData, &parsedJSON); err != nil {
			t.Fatalf("failed to unmarshal report JSON: %v", err)
		}

		// Recursively verify that no prohibited identity fields exist anywhere in the JSON hierarchy
		violations := findProhibitedIdentityKeyPaths(parsedJSON, prohibitedKeys, "")
		if len(violations) != 0 {
			t.Errorf("expected zero prohibited key violations in live report, found %d: %v", len(violations), violations)
		}
		assertNoProhibitedIdentityKeys(t, parsedJSON, prohibitedKeys)

		// Verify hostname is preserved as an allowed diagnostic field in system_info
		sysInfoMap, ok := parsedJSON["system_info"].(map[string]any)
		if !ok {
			t.Fatalf("system_info is not a valid map in report JSON")
		}
		hostnameVal, hasHostname := sysInfoMap["hostname"]
		if !hasHostname || hostnameVal == "" {
			t.Errorf("system_info must preserve allowed diagnostic field 'hostname'")
		}

		// Verify SYS_HOSTNAME_DISCOVERY details in JSON contains ONLY hostname
		checksList, ok := parsedJSON["checks"].([]any)
		if !ok {
			t.Fatalf("checks is not a list in report JSON")
		}
		for _, chk := range checksList {
			chkMap, ok := chk.(map[string]any)
			if !ok {
				continue
			}
			if chkMap["id"] == "SYS_HOSTNAME_DISCOVERY" {
				detailsMap, ok := chkMap["details"].(map[string]any)
				if !ok {
					t.Fatalf("SYS_HOSTNAME_DISCOVERY details is not a map in JSON")
				}
				if _, exists := detailsMap["current_user"]; exists {
					t.Errorf("SYS_HOSTNAME_DISCOVERY details in JSON contains 'current_user'")
				}
				if len(detailsMap) != 1 {
					t.Errorf("SYS_HOSTNAME_DISCOVERY details in JSON must contain only 'hostname', got %d: %v", len(detailsMap), detailsMap)
				}
				if _, exists := detailsMap["hostname"]; !exists {
					t.Errorf("SYS_HOSTNAME_DISCOVERY details in JSON must retain 'hostname'")
				}
			}
		}

		// 4. Terminal report validation
		termStr := FormatTerminal(liveRep)
		if strings.Contains(termStr, "current_user") {
			t.Errorf("terminal report contains raw 'current_user' field")
		}
		if strings.Contains(termStr, "Current User:") || strings.Contains(termStr, "Username:") {
			t.Errorf("terminal report contains prohibited user identity label")
		}
	})

	t.Run("HostnameLegitimatelyContainsUsernameWithoutFalsePositive", func(t *testing.T) {
		// Scenario: A host whose legitimate network hostname includes the operator's username
		// e.g., Hostname is "alice-workstation" and OS username is "alice".
		// Validation must NOT report a false positive because hostname is an allowed diagnostic field.
		simulatedUsername := "alice"
		simulatedHostname := "alice-workstation"

		// Explicitly verify the test precondition that simulatedHostname contains simulatedUsername
		if !strings.Contains(simulatedHostname, simulatedUsername) {
			t.Fatalf("test invariant failed: simulatedHostname %q must contain simulatedUsername %q", simulatedHostname, simulatedUsername)
		}

		mockInfo := monitor.SystemInfo{
			OS:        "linux",
			Arch:      "amd64",
			NumCPU:    4,
			Hostname:  simulatedHostname,
			Timestamp: time.Now().UTC(),
		}
		mockHealth := monitor.SystemHealth{
			Status:           "Healthy",
			ActiveInterfaces: 1,
			Timestamp:        time.Now().UTC(),
		}
		mockChecks := []privacy.CheckResult{
			privacy.NewCheckResult("SYS_HOSTNAME_DISCOVERY", "Local Hostname Identifier Check", privacy.CategorySystem, privacy.StatusInconclusive,
				fmt.Sprintf("Hostname %q contains potentially identifying environment keywords.", simulatedHostname)).
				WithDetails(map[string]any{
					"hostname": simulatedHostname,
				}),
			privacy.NewCheckResult("SYS_IFACE_EXPOSURE", "Network Interface Exposure Check", privacy.CategorySystem, privacy.StatusPass,
				"No active physical network interfaces detected.").
				WithDetails(map[string]any{
					"active_physical_interfaces": []string{},
					"active_vpn_interfaces":      []string{},
				}),
		}

		rep := NewAuditReport(mockInfo, mockHealth, mockChecks)
		jsonData, err := rep.ToJSON()
		if err != nil {
			t.Fatalf("ToJSON failed: %v", err)
		}

		var parsed map[string]any
		if err := json.Unmarshal(jsonData, &parsed); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		// Structural validation: verify zero prohibited key violations despite username substring in hostname
		violations := findProhibitedIdentityKeyPaths(parsed, prohibitedKeys, "")
		if len(violations) != 0 {
			t.Errorf("expected 0 prohibited key violations, found %d: %v", len(violations), violations)
		}
		assertNoProhibitedIdentityKeys(t, parsed, prohibitedKeys)

		// Hostname is preserved as allowed diagnostic field in system_info
		sysInfo := parsed["system_info"].(map[string]any)
		if sysInfo["hostname"] != simulatedHostname {
			t.Errorf("expected hostname %q, got %v", simulatedHostname, sysInfo["hostname"])
		}

		// SYS_HOSTNAME_DISCOVERY details contains only hostname
		checks := parsed["checks"].([]any)
		for _, chk := range checks {
			c := chk.(map[string]any)
			if c["id"] == "SYS_HOSTNAME_DISCOVERY" {
				det := c["details"].(map[string]any)
				if len(det) != 1 || det["hostname"] != simulatedHostname {
					t.Errorf("expected details to contain only hostname=%q, got: %v", simulatedHostname, det)
				}
				if _, hasUser := det["current_user"]; hasUser {
					t.Errorf("prohibited current_user field found in details")
				}
			}
		}

		// Terminal report coverage: verifies no user identity label is introduced
		termOut := FormatTerminal(rep)
		if strings.Contains(termOut, "current_user") || strings.Contains(termOut, "Current User:") || strings.Contains(termOut, "Username:") {
			t.Errorf("terminal report contains prohibited user identity label")
		}
		// Confirm the allowed diagnostic hostname is properly displayed in the terminal output
		if !strings.Contains(termOut, simulatedHostname) {
			t.Errorf("expected terminal report to display allowed diagnostic hostname %q", simulatedHostname)
		}
	})

	t.Run("RejectsProhibitedIdentityFieldsWhenPresent", func(t *testing.T) {
		// Validates that the actual findProhibitedIdentityKeyPaths helper correctly detects
		// a nested prohibited field (e.g. current_user inside check details)
		badTree := map[string]any{
			"report_id": "TEST-001",
			"system_info": map[string]any{
				"hostname": "node-01",
			},
			"checks": []any{
				map[string]any{
					"id": "SYS_HOSTNAME_DISCOVERY",
					"details": map[string]any{
						"hostname":     "node-01",
						"current_user": "attacker", // Prohibited nested field
					},
				},
			},
		}

		detectedViolations := findProhibitedIdentityKeyPaths(badTree, prohibitedKeys, "")
		if len(detectedViolations) != 1 {
			t.Fatalf("expected exactly 1 violation for injected current_user, got %d: %v", len(detectedViolations), detectedViolations)
		}
		expectedPath := "checks[0].details.current_user"
		if detectedViolations[0] != expectedPath {
			t.Errorf("expected violation at path %q, got %q", expectedPath, detectedViolations[0])
		}

		// Also verify that a clean report tree produces zero violations
		cleanTree := map[string]any{
			"report_id": "TEST-002",
			"system_info": map[string]any{
				"hostname": "node-01",
			},
			"checks": []any{
				map[string]any{
					"id": "SYS_HOSTNAME_DISCOVERY",
					"details": map[string]any{
						"hostname": "node-01",
					},
				},
			},
		}
		cleanViolations := findProhibitedIdentityKeyPaths(cleanTree, prohibitedKeys, "")
		if len(cleanViolations) != 0 {
			t.Errorf("expected zero violations on clean tree, got %d: %v", len(cleanViolations), cleanViolations)
		}
	})
}
