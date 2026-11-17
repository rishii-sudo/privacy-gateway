package isolation

import (
	"errors"
	"testing"
)

func TestUnimplementedManager(t *testing.T) {
	m := &UnimplementedManager{}
	if _, err := m.GetActiveProfile(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if err := m.SwitchProfile("test"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := m.ValidateSeparation(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
}
