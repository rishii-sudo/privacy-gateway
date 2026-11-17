package isolation

import (
	"errors"
)

var (
	// ErrNotImplemented indicates identity and lab isolation is scheduled for Milestone 7.
	ErrNotImplemented = errors.New("identity isolation is scheduled for Milestone 7 (M7)")
)

// EnvironmentType categorizes separated identity profiles.
type EnvironmentType string

const (
	EnvPersonal EnvironmentType = "personal"
	EnvResearch EnvironmentType = "research"
	EnvLab      EnvironmentType = "isolated_lab"
)

// Profile represents an isolated operational context.
type Profile struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Type        EnvironmentType `json:"type"`
	StrictProxy bool            `json:"strict_proxy"`
}

// Manager defines methods for maintaining strict isolation between personal and lab contexts.
type Manager interface {
	GetActiveProfile() (*Profile, error)
	SwitchProfile(id string) error
	ValidateSeparation() (bool, error)
}

// UnimplementedManager provides a baseline stub returning ErrNotImplemented.
type UnimplementedManager struct{}

func (u *UnimplementedManager) GetActiveProfile() (*Profile, error) {
	return nil, ErrNotImplemented
}

func (u *UnimplementedManager) SwitchProfile(id string) error {
	return ErrNotImplemented
}

func (u *UnimplementedManager) ValidateSeparation() (bool, error) {
	return false, ErrNotImplemented
}
