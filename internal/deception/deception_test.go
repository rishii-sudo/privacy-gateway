package deception

import (
	"errors"
	"testing"
)

func TestUnimplementedLab(t *testing.T) {
	l := &UnimplementedLab{}
	if err := l.StartDecoy(DecoySSH, "127.0.0.1:2222"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if err := l.StopDecoy(DecoySSH); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := l.GetEvents(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
}
