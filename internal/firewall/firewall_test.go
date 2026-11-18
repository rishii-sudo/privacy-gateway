package firewall_test

import (
	"errors"
	"testing"

	"github.com/rishii-sudo/privacy-gateway/internal/firewall"
	"github.com/rishii-sudo/privacy-gateway/internal/firewall/linux"
	"github.com/rishii-sudo/privacy-gateway/internal/firewall/windows"
)

func TestAdapters(t *testing.T) {
	adapters := []firewall.Adapter{
		linux.NewNftablesAdapter(),
		windows.NewWFPAdapter(),
	}

	for _, a := range adapters {
		t.Run(a.Name(), func(t *testing.T) {
			if a.Name() == "" {
				t.Errorf("adapter name is empty")
			}
			if err := a.EnableKillSwitch(firewall.Policy{Mode: "simulate"}); !errors.Is(err, firewall.ErrNotImplemented) {
				t.Errorf("expected ErrNotImplemented on EnableKillSwitch, got %v", err)
			}
			if err := a.DisableKillSwitch(); !errors.Is(err, firewall.ErrNotImplemented) {
				t.Errorf("expected ErrNotImplemented on DisableKillSwitch, got %v", err)
			}
			if _, err := a.IsActive(); !errors.Is(err, firewall.ErrNotImplemented) {
				t.Errorf("expected ErrNotImplemented on IsActive, got %v", err)
			}
			if err := a.Rollback(); !errors.Is(err, firewall.ErrNotImplemented) {
				t.Errorf("expected ErrNotImplemented on Rollback, got %v", err)
			}
		})
	}
}
