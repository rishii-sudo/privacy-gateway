package footprint

import (
	"errors"
)

var (
	// ErrNotImplemented indicates digital footprint auditing is scheduled for Milestone 7.
	ErrNotImplemented = errors.New("digital footprint auditing is scheduled for Milestone 7 (M7)")
)

// ExposureItem represents an observed public exposure indicator.
type ExposureItem struct {
	Source      string `json:"source"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// Auditor defines the interface for legitimate privacy exposure auditing.
type Auditor interface {
	InspectLocalMetadata(filePath string) (map[string]string, error)
	AuditExposure(targetIdentifier string) ([]ExposureItem, error)
}

// UnimplementedAuditor provides a baseline stub returning ErrNotImplemented.
type UnimplementedAuditor struct{}

func (u *UnimplementedAuditor) InspectLocalMetadata(filePath string) (map[string]string, error) {
	return nil, ErrNotImplemented
}

func (u *UnimplementedAuditor) AuditExposure(targetIdentifier string) ([]ExposureItem, error) {
	return nil, ErrNotImplemented
}
