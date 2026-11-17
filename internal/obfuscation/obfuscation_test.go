package obfuscation

import (
	"errors"
	"testing"
)

func TestUnimplementedObfuscator(t *testing.T) {
	o := &UnimplementedObfuscator{}
	if err := o.ValidateConfig(Config{}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
	if _, err := o.CheckHealth(Config{}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
}
