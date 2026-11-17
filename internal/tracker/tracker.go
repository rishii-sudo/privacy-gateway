package tracker

import (
	"errors"
)

var (
	// ErrNotImplemented indicates tracker blocking is scheduled for Milestone 6.
	ErrNotImplemented = errors.New("tracker blocking is scheduled for Milestone 6 (M6)")
)

// Statistics contains telemetry on blocked tracking queries.
type Statistics struct {
	TotalQueries   uint64 `json:"total_queries"`
	BlockedQueries uint64 `json:"blocked_queries"`
	BlocklistCount int    `json:"blocklist_count"`
}

// Blocker defines the interface for DNS-based and browser-level tracker mitigation.
type Blocker interface {
	LoadBlocklist(source string) error
	IsDomainBlocked(domain string) (bool, error)
	GetStatistics() (Statistics, error)
}

// UnimplementedBlocker provides a baseline stub returning ErrNotImplemented.
type UnimplementedBlocker struct{}

func (u *UnimplementedBlocker) LoadBlocklist(source string) error {
	return ErrNotImplemented
}

func (u *UnimplementedBlocker) IsDomainBlocked(domain string) (bool, error) {
	return false, ErrNotImplemented
}

func (u *UnimplementedBlocker) GetStatistics() (Statistics, error) {
	return Statistics{}, ErrNotImplemented
}
