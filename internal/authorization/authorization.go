package authorization

import (
	"errors"
)

var (
	// ErrNotImplemented indicates fine-grained authorization policies are scheduled for Milestone 9.
	ErrNotImplemented = errors.New("authorization policy engine is scheduled for Milestone 9 (M9)")
)

// PrivilegeLevel denotes operational privilege.
type PrivilegeLevel string

const (
	PrivilegeReadOnly   PrivilegeLevel = "read_only"
	PrivilegeOperator   PrivilegeLevel = "operator"
	PrivilegePrivileged PrivilegeLevel = "privileged"
)

// PolicyEngine enforces access control before privileged system modifications.
type PolicyEngine interface {
	Authorize(level PrivilegeLevel, operation string) (bool, error)
	ConfirmExplicitApproval(operation string) (bool, error)
}
