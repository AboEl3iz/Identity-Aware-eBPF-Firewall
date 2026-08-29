package security

import (
	"os"
	"testing"
)

func TestRBACRoleResolution(t *testing.T) {
	enforcer := NewRBACEnforcer()

	// Root identity (UID 0) -> Admin
	rootPeer := &PeerIdentity{UID: 0, GID: 0, PID: 100}
	if role := enforcer.ResolveRole(rootPeer); role != RoleAdmin {
		t.Fatalf("expected root to be RoleAdmin, got %s", role)
	}

	// Registered operator UID -> Operator
	enforcer.AddOperatorUID(1001)
	opPeer := &PeerIdentity{UID: 1001, GID: 1001, PID: 200}
	if role := enforcer.ResolveRole(opPeer); role != RoleOperator {
		t.Fatalf("expected UID 1001 to be RoleOperator, got %s", role)
	}

	// Unregistered standard UID -> Viewer
	viewerPeer := &PeerIdentity{UID: 1002, GID: 1002, PID: 300}
	if role := enforcer.ResolveRole(viewerPeer); role != RoleViewer {
		t.Fatalf("expected UID 1002 to be RoleViewer, got %s", role)
	}
}

func TestRBACPermissionMatrix(t *testing.T) {
	enforcer := NewRBACEnforcer()

	// 1. Admin allowed all commands
	if err := enforcer.EvaluatePermission(RoleAdmin, "apply_policy"); err != nil {
		t.Errorf("Admin should be allowed 'apply_policy': %v", err)
	}
	if err := enforcer.EvaluatePermission(RoleAdmin, "get_status"); err != nil {
		t.Errorf("Admin should be allowed 'get_status': %v", err)
	}

	// 2. Operator allowed apply_policy and get_status
	if err := enforcer.EvaluatePermission(RoleOperator, "apply_policy"); err != nil {
		t.Errorf("Operator should be allowed 'apply_policy': %v", err)
	}
	if err := enforcer.EvaluatePermission(RoleOperator, "dump_maps"); err != nil {
		t.Errorf("Operator should be allowed 'dump_maps': %v", err)
	}

	// 3. Viewer allowed get_status & dump_maps, but REJECTED for apply_policy
	if err := enforcer.EvaluatePermission(RoleViewer, "get_status"); err != nil {
		t.Errorf("Viewer should be allowed 'get_status': %v", err)
	}
	if err := enforcer.EvaluatePermission(RoleViewer, "dump_maps"); err != nil {
		t.Errorf("Viewer should be allowed 'dump_maps': %v", err)
	}
	if err := enforcer.EvaluatePermission(RoleViewer, "apply_policy"); err == nil {
		t.Errorf("Viewer should be REJECTED for 'apply_policy', but passed!")
	}
}

func TestCapabilityInspection(t *testing.T) {
	caps, err := GetProcessCapabilities()
	if err != nil {
		t.Fatalf("failed to read process capabilities: %v", err)
	}

	t.Logf("Process UID: %d, Root: %v", os.Geteuid(), caps.IsRoot)
	t.Logf("Effective capabilities count: %d", len(caps.Effective))
}
