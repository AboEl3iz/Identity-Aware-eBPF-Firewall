package security

import (
	"fmt"
	"strings"
	"sync"
)

// Role represents an authorization tier in the eBPF firewall control plane.
type Role string

const (
	RoleAdmin    Role = "Admin"
	RoleOperator Role = "Operator"
	RoleViewer   Role = "Viewer"
)

// RBACEnforcer evaluates caller identity credentials against permission policies.
type RBACEnforcer struct {
	mu           sync.RWMutex
	adminUIDs    map[uint32]bool
	operatorUIDs map[uint32]bool
	adminGIDs    map[uint32]bool
	operatorGIDs map[uint32]bool
}

// NewRBACEnforcer creates a default RBAC policy enforcer with sensible Linux defaults.
func NewRBACEnforcer() *RBACEnforcer {
	return &RBACEnforcer{
		adminUIDs:    map[uint32]bool{0: true}, // UID 0 (root) defaults to Admin
		operatorUIDs: make(map[uint32]bool),
		adminGIDs:    map[uint32]bool{0: true, 27: true}, // root and sudo (GID 27) default to Admin
		operatorGIDs: make(map[uint32]bool),
	}
}

// AddAdminUID registers a UID as an Admin.
func (e *RBACEnforcer) AddAdminUID(uid uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.adminUIDs[uid] = true
}

// AddOperatorUID registers a UID as an Operator.
func (e *RBACEnforcer) AddOperatorUID(uid uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.operatorUIDs[uid] = true
}

// ResolveRole maps a verified peer identity (UID, GID) to an RBAC role.
func (e *RBACEnforcer) ResolveRole(identity *PeerIdentity) Role {
	if identity == nil {
		return RoleViewer
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Check explicit UID rules first
	if e.adminUIDs[identity.UID] {
		return RoleAdmin
	}
	if e.operatorUIDs[identity.UID] {
		return RoleOperator
	}

	// Check explicit GID rules
	if e.adminGIDs[identity.GID] {
		return RoleAdmin
	}
	if e.operatorGIDs[identity.GID] {
		return RoleOperator
	}

	// Default fallback role for unassigned authenticated users is Viewer
	return RoleViewer
}

// EvaluatePermission checks if the given role is authorized to run command.
func (e *RBACEnforcer) EvaluatePermission(role Role, command string) error {
	cmd := strings.ToLower(command)
	switch cmd {
	case "apply_policy":
		if role == RoleAdmin || role == RoleOperator {
			return nil
		}
		return fmt.Errorf("403 Forbidden: role '%s' is not authorized for command '%s'", role, command)

	case "get_status", "dump_maps":
		if role == RoleAdmin || role == RoleOperator || role == RoleViewer {
			return nil
		}
		return fmt.Errorf("403 Forbidden: role '%s' is not authorized for command '%s'", role, command)

	default:
		return fmt.Errorf("403 Forbidden: unknown command '%s'", command)
	}
}
