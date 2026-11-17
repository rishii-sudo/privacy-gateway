package privacy

import (
	"encoding/json"
	"testing"
)

func TestStatusValidity(t *testing.T) {
	validStatuses := []Status{StatusPass, StatusFail, StatusInconclusive, StatusNotImplemented}
	for _, s := range validStatuses {
		if !s.IsValid() {
			t.Errorf("expected status %s to be valid", s)
		}
	}

	invalid := Status("UNKNOWN")
	if invalid.IsValid() {
		t.Errorf("expected UNKNOWN status to be invalid")
	}
}

func TestStatusJSONMarshaling(t *testing.T) {
	res := NewCheckResult("TEST_1", "Test Check", CategorySystem, StatusPass, "All good")
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("failed to marshal CheckResult: %v", err)
	}

	var decoded CheckResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal CheckResult: %v", err)
	}

	if decoded.Status != StatusPass {
		t.Errorf("expected status PASS, got %s", decoded.Status)
	}
	if decoded.Category != CategorySystem {
		t.Errorf("expected category System, got %s", decoded.Category)
	}
}

func TestInvalidStatusJSONUnmarshal(t *testing.T) {
	badJSON := []byte(`"INVALID_STATUS"`)
	var s Status
	if err := json.Unmarshal(badJSON, &s); err == nil {
		t.Fatalf("expected error unmarshaling invalid status, got nil")
	}
}

func TestAggregateStatus(t *testing.T) {
	tests := []struct {
		name     string
		statuses []Status
		expected Status
	}{
		{
			name:     "empty slice",
			statuses: []Status{},
			expected: StatusInconclusive,
		},
		{
			name:     "all pass",
			statuses: []Status{StatusPass, StatusPass},
			expected: StatusPass,
		},
		{
			name:     "any fail triggers fail",
			statuses: []Status{StatusPass, StatusFail, StatusPass},
			expected: StatusFail,
		},
		{
			name:     "inconclusive over pass when no fail",
			statuses: []Status{StatusPass, StatusInconclusive},
			expected: StatusInconclusive,
		},
		{
			name:     "fail over inconclusive",
			statuses: []Status{StatusInconclusive, StatusFail},
			expected: StatusFail,
		},
		{
			name:     "all not implemented",
			statuses: []Status{StatusNotImplemented, StatusNotImplemented},
			expected: StatusNotImplemented,
		},
		{
			name:     "pass with not implemented returns pass",
			statuses: []Status{StatusPass, StatusNotImplemented},
			expected: StatusPass,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var results []CheckResult
			for i, s := range tc.statuses {
				results = append(results, NewCheckResult(string(rune(i)), "check", CategoryNetwork, s, "summary"))
			}
			agg := AggregateStatus(results)
			if agg != tc.expected {
				t.Errorf("AggregateStatus() = %s, want %s", agg, tc.expected)
			}
		})
	}
}
