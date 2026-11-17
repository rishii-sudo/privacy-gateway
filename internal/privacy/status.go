package privacy

import (
	"encoding/json"
	"fmt"
	"time"
)

// Status represents the strongly-typed verification outcome for a security or privacy check.
type Status string

const (
	// StatusPass indicates the tested requirement was completely satisfied.
	StatusPass Status = "PASS"

	// StatusFail indicates a verified security or privacy problem was detected.
	StatusFail Status = "FAIL"

	// StatusInconclusive indicates the check could not reach a reliable conclusion.
	// This includes network timeouts, unreachable endpoints, or ambiguous states.
	StatusInconclusive Status = "INCONCLUSIVE"

	// StatusNotImplemented indicates the capability is scheduled for a future milestone
	// and has not yet been implemented.
	StatusNotImplemented Status = "NOT_IMPLEMENTED"
)

// IsValid returns true if the status is one of the four defined verification states.
func (s Status) IsValid() bool {
	switch s {
	case StatusPass, StatusFail, StatusInconclusive, StatusNotImplemented:
		return true
	default:
		return false
	}
}

// String returns the string representation of Status.
func (s Status) String() string {
	return string(s)
}

// MarshalJSON ensures proper JSON serialization.
func (s Status) MarshalJSON() ([]byte, error) {
	if !s.IsValid() {
		return nil, fmt.Errorf("invalid privacy verification status: %q", string(s))
	}
	return json.Marshal(string(s))
}

// UnmarshalJSON validates during deserialization.
func (s *Status) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	st := Status(str)
	if !st.IsValid() {
		return fmt.Errorf("invalid privacy verification status: %q", str)
	}
	*s = st
	return nil
}

// Category represents the domain category of a privacy or security check.
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
	CategoryIsolation   Category = "Isolation"
	CategoryFootprint   Category = "Footprint"
	CategoryDeception   Category = "Deception"
	CategoryAudit       Category = "Audit"
)

// CheckResult encapsulates the comprehensive result of a verification check.
type CheckResult struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Category    Category               `json:"category"`
	Status      Status                 `json:"status"`
	Summary     string                 `json:"summary"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	Timestamp   time.Time              `json:"timestamp"` // Captured in UTC
}

// NewCheckResult creates a new CheckResult with normalized UTC timestamp and validated status.
func NewCheckResult(id, name string, cat Category, st Status, summary string) CheckResult {
	if !st.IsValid() {
		st = StatusInconclusive
	}
	return CheckResult{
		ID:        id,
		Name:      name,
		Category:  cat,
		Status:    st,
		Summary:   summary,
		Details:   make(map[string]interface{}),
		Timestamp: time.Now().UTC(),
	}
}

// WithDetails attaches structured diagnostic details to the result.
func (r CheckResult) WithDetails(details map[string]interface{}) CheckResult {
	r.Details = details
	return r
}

// WithRemediation attaches actionable remediation steps to the result.
func (r CheckResult) WithRemediation(remediation string) CheckResult {
	r.Remediation = remediation
	return r
}

// AggregateStatus computes the overall status from a collection of check results.
// Rules:
// 1. If any check is FAIL, the overall status is FAIL.
// 2. If no FAIL, but at least one INCONCLUSIVE, overall is INCONCLUSIVE.
// 3. If no FAIL or INCONCLUSIVE, but all are NOT_IMPLEMENTED, overall is NOT_IMPLEMENTED.
// 4. If all implemented checks PASS, overall is PASS.
func AggregateStatus(results []CheckResult) Status {
	if len(results) == 0 {
		return StatusInconclusive
	}

	hasFail := false
	hasInconclusive := false
	hasPass := false
	allNotImplemented := true

	for _, res := range results {
		switch res.Status {
		case StatusFail:
			hasFail = true
			allNotImplemented = false
		case StatusInconclusive:
			hasInconclusive = true
			allNotImplemented = false
		case StatusPass:
			hasPass = true
			allNotImplemented = false
		case StatusNotImplemented:
			// stays true unless another status is observed
		}
	}

	if hasFail {
		return StatusFail
	}
	if hasInconclusive {
		return StatusInconclusive
	}
	if allNotImplemented {
		return StatusNotImplemented
	}
	if hasPass {
		return StatusPass
	}

	return StatusInconclusive
}
