package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"policy_engine/pkg/control"
	"policy_engine/pkg/security"
)

func TestPhase6SecurityRBAC(t *testing.T) {
	// 1. Verify capability inspection logic
	caps, err := security.GetProcessCapabilities()
	if err != nil {
		t.Fatalf("Failed to read process capabilities: %v", err)
	}
	t.Logf("[+] Process capability inspection successful (UID: %d, Root: %v, BPF: %v, NetAdmin: %v)",
		os.Geteuid(), caps.IsRoot, caps.HasCapBPF, caps.HasCapNet)

	// 2. Setup temporary Unix domain socket for IPC security testing
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "firewall-agent-test.sock")

	ctrlServer := control.NewControlServer(sockPath, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := ctrlServer.Start(ctx); err != nil {
			t.Logf("Control server stopped: %v", err)
		}
	}()

	// Wait for socket to become ready
	time.Sleep(100 * time.Millisecond)

	client := control.NewControlClient(sockPath)

	// 3. Test authenticated caller peer credentials & status query (Viewer/Admin allowed)
	statusResp, err := client.GetStatus()
	if err != nil {
		t.Fatalf("Failed to call GetStatus over socket: %v", err)
	}
	if !statusResp.Success {
		t.Fatalf("GetStatus returned error: %s", statusResp.Error)
	}
	if statusResp.CallerUID != uint32(os.Geteuid()) {
		t.Errorf("SO_PEERCRED mismatch: expected UID %d, got %d", os.Geteuid(), statusResp.CallerUID)
	}
	t.Logf("[+] Authenticated socket peer: UID=%d PID=%d Role=%s", statusResp.CallerUID, statusResp.CallerPID, statusResp.CallerRole)

	// 4. Test RBAC policy mutation rejection for RoleViewer
	// Configure current UID to be explicitly mapped to RoleViewer
	ctrlServer.RBAC().AddAdminUID(999999) // ensure current UID is not admin
	currentUID := uint32(os.Geteuid())

	// Create an enforcer that maps current UID to Viewer
	rbacViewer := security.NewRBACEnforcer()
	// evaluate permission directly on Viewer role
	errViewer := rbacViewer.EvaluatePermission(security.RoleViewer, "apply_policy")
	if errViewer == nil {
		t.Fatalf("Expected RoleViewer to be rejected for apply_policy, but passed!")
	}
	if !strings.Contains(errViewer.Error(), "403 Forbidden") {
		t.Fatalf("Expected '403 Forbidden' error string, got: %v", errViewer)
	}
	t.Logf("[+] Verified RBAC rejection for RoleViewer: %v", errViewer)

	// 5. Test RBAC policy mutation permission for RoleAdmin & RoleOperator
	rbacAdmin := security.NewRBACEnforcer()
	if err := rbacAdmin.EvaluatePermission(security.RoleAdmin, "apply_policy"); err != nil {
		t.Fatalf("RoleAdmin should be allowed for apply_policy: %v", err)
	}
	if err := rbacAdmin.EvaluatePermission(security.RoleOperator, "apply_policy"); err != nil {
		t.Fatalf("RoleOperator should be allowed for apply_policy: %v", err)
	}
	t.Logf("[+] Verified RBAC permissions for RoleAdmin & RoleOperator on policy apply.")

	// 6. Test direct socket apply_policy with current UID registered as Admin
	ctrlServer.RBAC().AddAdminUID(currentUID)
	dummyYAML := `apiVersion: v1
kind: FirewallPolicy
metadata:
  name: test-security-policy
spec:
  defaultAction: allow
  rules: []
`
	applyResp, err := client.SendRequest(control.Request{
		Command:    "apply_policy",
		PolicyYAML: dummyYAML,
	})
	if err != nil {
		t.Fatalf("Failed to send apply_policy request: %v", err)
	}
	t.Logf("[+] Authorized IPC apply_policy execution response (Caller Role: %s, Success: %v)",
		applyResp.CallerRole, applyResp.Success)
}
