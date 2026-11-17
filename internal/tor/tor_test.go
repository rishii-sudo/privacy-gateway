package tor

import (
	"errors"
	"testing"
)

func TestUnimplementedController(t *testing.T) {
	c := &UnimplementedController{}
	if err := c.Connect("127.0.0.1:9051", ""); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := c.GetBootstrapStatus(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := c.GetActiveCircuits(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if err := c.RequestNewIdentity(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("expected nil error on Close, got %v", err)
	}
}
