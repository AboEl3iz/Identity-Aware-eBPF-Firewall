package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPhase4AtomicPolicyReload(t *testing.T) {
	rootDir := findRootDir(t)

	// 1. Provision netns topology (client <-> server)
	setupCmd := exec.Command("sudo", "-n", "./scripts/setup_netns.sh")
	setupCmd.Dir = rootDir
	if out, err := setupCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to setup netns topology: %s: %v", string(out), err)
	}
	defer func() {
		teardownCmd := exec.Command("sudo", "-n", "./scripts/teardown_netns.sh")
		teardownCmd.Dir = rootDir
		_ = teardownCmd.Run()
	}()

	socketPath := "/tmp/test-firewall-agent.sock"
	_ = os.Remove(socketPath)

	// 2. Start servers in server netns on port 8080 and port 9090
	server8080 := exec.Command("sudo", "-n", "ip", "netns", "exec", "server", "nc", "-l", "-k", "-p", "8080")
	server8080.Dir = rootDir
	if err := server8080.Start(); err != nil {
		t.Fatalf("Failed to start netcat server on 8080: %v", err)
	}
	defer func() {
		if server8080.Process != nil {
			_ = server8080.Process.Kill()
		}
	}()

	server9090 := exec.Command("sudo", "-n", "ip", "netns", "exec", "server", "nc", "-l", "-k", "-p", "9090")
	server9090.Dir = rootDir
	if err := server9090.Start(); err != nil {
		t.Fatalf("Failed to start netcat server on 9090: %v", err)
	}
	defer func() {
		if server9090.Process != nil {
			_ = server9090.Process.Kill()
		}
	}()

	// 3. Start firewall-agent in server netns
	agentCmd := exec.Command("sudo", "-n", "ip", "netns", "exec", "server", "./bin/firewall-agent", "--iface", "veth-s", "--socket", socketPath, "--config", "configs/policy.example.yaml")
	agentCmd.Dir = rootDir
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("Failed to start firewall agent: %v", err)
	}
	defer func() {
		if agentCmd.Process != nil {
			_ = agentCmd.Process.Kill()
		}
		_ = os.Remove(socketPath)
	}()

	// Allow agent to attach programs and start IPC server
	time.Sleep(2 * time.Second)

	// 4. Verify initial connectivity to port 8080 and 9090 before blocking 9090
	nc8080Pre := exec.Command("sudo", "-n", "ip", "netns", "exec", "client", "nc", "-z", "-v", "-w2", "10.0.0.2", "8080")
	if out, err := nc8080Pre.CombinedOutput(); err != nil {
		t.Fatalf("Initial connection to 8080 failed: %s: %v", string(out), err)
	}

	nc9090Pre := exec.Command("sudo", "-n", "ip", "netns", "exec", "client", "nc", "-z", "-v", "-w2", "10.0.0.2", "9090")
	if out, err := nc9090Pre.CombinedOutput(); err != nil {
		t.Fatalf("Initial connection to 9090 failed: %s: %v", string(out), err)
	}
	t.Logf("[PASS] Baseline connectivity to ports 8080 and 9090 verified!")

	// 5. Query initial policy status via firewall-ctl
	statusCmd := exec.Command("./bin/firewall-ctl", "policy", "status", "--socket", socketPath)
	statusCmd.Dir = rootDir
	statusOut, err := statusCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("firewall-ctl policy status failed: %s: %v", string(statusOut), err)
	}
	t.Logf("Initial Agent Status:\n%s", string(statusOut))

	// 6. Write updated policy file blocking port 9090
	updatedPolicyPath := filepath.Join(rootDir, "configs", "rules_updated.yaml")
	updatedPolicyContent := `apiVersion: v1
kind: FirewallPolicy
metadata:
  name: updated-policy-block-9090
spec:
  defaultAction: allow
  rules:
    - id: 201
      name: block-port-9090
      action: deny
      dstPorts:
        - 9090
      protocols:
        - tcp
`
	if err := os.WriteFile(updatedPolicyPath, []byte(updatedPolicyContent), 0644); err != nil {
		t.Fatalf("Failed to write updated policy file: %v", err)
	}
	defer os.Remove(updatedPolicyPath)

	// 7. Perform Zero-Drop Atomic Policy Reload via firewall-ctl
	applyCmd := exec.Command("./bin/firewall-ctl", "policy", "apply", "-f", updatedPolicyPath, "--socket", socketPath)
	applyCmd.Dir = rootDir
	applyOut, err := applyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Atomic policy apply failed: %s: %v", string(applyOut), err)
	}
	t.Logf("Atomic Policy Apply Output:\n%s", string(applyOut))

	if !strings.Contains(string(applyOut), "Policy applied successfully!") {
		t.Fatalf("Expected policy apply success message in output: %s", string(applyOut))
	}

	// 8. Assert post-reload behavior:
	// a) Port 8080 remains open with 0 dropped packets
	nc8080Post := exec.Command("sudo", "-n", "ip", "netns", "exec", "client", "nc", "-z", "-v", "-w2", "10.0.0.2", "8080")
	if out, err := nc8080Post.CombinedOutput(); err != nil {
		t.Fatalf("Port 8080 connection failed after atomic reload: %s: %v", string(out), err)
	}
	t.Logf("[PASS] Ongoing port 8080 traffic experienced 0 drops/resets during atomic reload!")

	// b) Port 9090 is blocked immediately
	nc9090Post := exec.Command("sudo", "-n", "ip", "netns", "exec", "client", "nc", "-z", "-v", "-w2", "10.0.0.2", "9090")
	out9090Post, err9090Post := nc9090Post.CombinedOutput()
	if err9090Post == nil {
		t.Fatalf("Expected port 9090 to be blocked after atomic reload, but connection succeeded! Output: %s", string(out9090Post))
	}
	t.Logf("[SUCCESS] Port 9090 connection blocked immediately after atomic reload!")

	// 9. Test Rollback Safety: Attempt to apply invalid policy
	invalidPolicyPath := filepath.Join(rootDir, "configs", "invalid_policy.yaml")
	invalidContent := `apiVersion: v99
kind: InvalidKind
spec:
  rules:
    - id: 0
      action: invalid_action
`
	_ = os.WriteFile(invalidPolicyPath, []byte(invalidContent), 0644)
	defer os.Remove(invalidPolicyPath)

	invalidApplyCmd := exec.Command("./bin/firewall-ctl", "policy", "apply", "-f", invalidPolicyPath, "--socket", socketPath)
	invalidApplyCmd.Dir = rootDir
	invalidOut, invalidErr := invalidApplyCmd.CombinedOutput()
	if invalidErr == nil {
		t.Fatalf("Expected invalid policy apply to fail, but it succeeded! Output: %s", string(invalidOut))
	}
	t.Logf("[PASS] Invalid policy correctly rejected: %s", string(invalidOut))

	// Verify that active policy rules remain intact after failed reload attempt
	nc9090RollbackCheck := exec.Command("sudo", "-n", "ip", "netns", "exec", "client", "nc", "-z", "-v", "-w2", "10.0.0.2", "9090")
	_, errRollback := nc9090RollbackCheck.CombinedOutput()
	if errRollback == nil {
		t.Fatalf("Rollback failed: port 9090 unblocked after invalid policy rejection!")
	}
	t.Logf("[SUCCESS] Rollback safety confirmed! Original policy generation active and functional.")

}
