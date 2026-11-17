package vpn

import (
	"errors"
	"testing"
)

func TestUnimplementedManager(t *testing.T) {
	m := &UnimplementedManager{}
	if _, err := m.DetectVPNInterfaces(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := m.GetTunnelStatus(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := m.VerifyTunnelRoute(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
}
