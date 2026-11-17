package privacy

import (
	"strings"
	"testing"

	"github.com/48sh1xbh/privacy-gateway/internal/config"
)

func TestCheckerBaselineRuns(t *testing.T) {
	cfg := config.DefaultConfig()
	checker := NewChecker(cfg)

	results, err := checker.RunAllBaselineChecks()
	if err != nil {
		t.Fatalf("RunAllBaselineChecks failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("expected non-empty results from baseline checks")
	}

	// Verify each result has valid status and UTC timestamp
	foundNotImplemented := false
	for _, r := range results {
		if !r.Status.IsValid() {
			t.Errorf("result %s has invalid status %s", r.ID, r.Status)
		}
		if r.Timestamp.IsZero() {
			t.Errorf("result %s has zero timestamp", r.ID)
		}
		if r.Status == StatusNotImplemented {
			foundNotImplemented = true
		}
	}

	if !foundNotImplemented {
		t.Errorf("expected stubbed checks with StatusNotImplemented for future milestones")
	}
}

func TestCheckDNSResolverPrivacy(t *testing.T) {
	// Important correction 1: A private DNS resolver does not prove plaintext ISP DNS -> INCONCLUSIVE
	cfg := config.DefaultConfig()
	cfg.Network.DnsServers = []string{"192.168.1.1"}
	checker := NewChecker(cfg)

	res := checker.CheckDNSResolverPrivacy()
	if res.Status != StatusInconclusive {
		t.Errorf("expected INCONCLUSIVE for private resolver without active query inspection, got %s", res.Status)
	}

	// Important correction 2: A public DNS resolver does not prove encrypted DNS -> INCONCLUSIVE
	cfg.Network.DnsServers = []string{"1.1.1.1", "9.9.9.9"}
	checker = NewChecker(cfg)
	res = checker.CheckDNSResolverPrivacy()
	if res.Status != StatusInconclusive {
		t.Errorf("expected INCONCLUSIVE for public resolver without encrypted transport verification, got %s", res.Status)
	}
}

func TestCheckHostnameExposure(t *testing.T) {
	checker := NewChecker(nil)
	res := checker.CheckHostnameExposure()
	if !res.Status.IsValid() {
		t.Errorf("unexpected invalid status from CheckHostnameExposure: %s", res.Status)
	}
	// Conservative check: Identifying vendor/device name -> INCONCLUSIVE; generic -> PASS
	if res.Status != StatusPass && res.Status != StatusInconclusive {
		t.Errorf("expected PASS or INCONCLUSIVE for hostname check, got %s", res.Status)
	}
}

func TestCheckIPv6Exposure(t *testing.T) {
	checker := NewChecker(nil)
	res := checker.CheckIPv6Exposure()
	if !res.Status.IsValid() {
		t.Errorf("unexpected invalid status from CheckIPv6Exposure: %s", res.Status)
	}
	// Important correction: A global IPv6 address does not automatically establish a leak -> Must be PASS (none) or INCONCLUSIVE (present)
	if res.Status != StatusPass && res.Status != StatusInconclusive {
		t.Errorf("expected PASS or INCONCLUSIVE for IPv6 exposure check, got %s", res.Status)
	}
}

func TestCheckInterfaceExposure(t *testing.T) {
	checker := NewChecker(nil)
	res := checker.CheckInterfaceExposure()
	if !res.Status.IsValid() {
		t.Errorf("unexpected invalid status from CheckInterfaceExposure: %s", res.Status)
	}
	// Must be PASS (no physical interfaces), FAIL (physical with no VPN), or INCONCLUSIVE (VPN present or unknown adapter)
	if res.Status != StatusPass && res.Status != StatusFail && res.Status != StatusInconclusive {
		t.Errorf("unexpected status for interface exposure: %s", res.Status)
	}

	// Verify remediation text does NOT falsely claim launching Tor automatically shields all system traffic
	if res.Remediation != "" {
		if strings.Contains(res.Remediation, "launch Tor to shield physical interface traffic") {
			t.Errorf("remediation must not claim Tor automatically shields all system traffic")
		}
		if res.Status == StatusFail {
			if !strings.Contains(res.Remediation, "system-wide VPN") && !strings.Contains(res.Remediation, "routing policy") {
				t.Errorf("remediation must explain verified system-wide VPN route or enforced routing policy is required")
			}
		}
	}
}
