package footprint

import (
	"errors"
	"testing"
)

func TestUnimplementedAuditor(t *testing.T) {
	a := &UnimplementedAuditor{}
	if _, err := a.InspectLocalMetadata("file.txt"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := a.AuditExposure("user"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
}
