package linux

import (
	"github.com/rishii-sudo/privacy-gateway/internal/firewall"
)

// NftablesAdapter implements firewall.Adapter for Linux nftables.
type NftablesAdapter struct{}

func NewNftablesAdapter() *NftablesAdapter {
	return &NftablesAdapter{}
}

func (n *NftablesAdapter) Name() string {
	return "linux_nftables"
}

func (n *NftablesAdapter) EnableKillSwitch(policy firewall.Policy) error {
	return firewall.ErrNotImplemented
}

func (n *NftablesAdapter) DisableKillSwitch() error {
	return firewall.ErrNotImplemented
}

func (n *NftablesAdapter) IsActive() (bool, error) {
	return false, firewall.ErrNotImplemented
}

func (n *NftablesAdapter) Rollback() error {
	return firewall.ErrNotImplemented
}
