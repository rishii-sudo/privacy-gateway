package tracker

import (
	"errors"
	"testing"
)

func TestUnimplementedBlocker(t *testing.T) {
	b := &UnimplementedBlocker{}
	if err := b.LoadBlocklist("default"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := b.IsDomainBlocked("example.com"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := b.GetStatistics(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
}
