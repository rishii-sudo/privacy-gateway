package windows

import (
	"github.com/48sh1xbh/privacy-gateway/internal/firewall"
)

// WFPAdapter implements firewall.Adapter for Windows Filtering Platform.
type WFPAdapter struct{}

func NewWFPAdapter() *WFPAdapter {
	return &WFPAdapter{}
}

func (w *WFPAdapter) Name() string {
	return "windows_wfp"
}

func (w *WFPAdapter) EnableKillSwitch(policy firewall.Policy) error {
	return firewall.ErrNotImplemented
}

func (w *WFPAdapter) DisableKillSwitch() error {
	return firewall.ErrNotImplemented
}

func (w *WFPAdapter) IsActive() (bool, error) {
	return false, firewall.ErrNotImplemented
}

func (w *WFPAdapter) Rollback() error {
	return firewall.ErrNotImplemented
}
