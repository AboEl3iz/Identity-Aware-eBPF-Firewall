package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPhase3CgroupIdentity(t *testing.T) {
	rootDir := findRootDir(t)

	// Setup cgroup v2 directories
	cgCmd := exec.Command("sudo", "./scripts/setup_cgroup.sh")
	cgCmd.Dir = rootDir
	if out, err := cgCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to setup cgroup v2 directories: %s: %v", string(out), err)
	}

	// Setup netns topology
	setupCmd := exec.Command("sudo", "./scripts/setup_netns.sh")
	setupCmd.Dir = rootDir
	if out, err := setupCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to setup netns topology: %s: %v", string(out), err)
	}
	defer func() {
		teardownCmd := exec.Command("sudo", "./scripts/teardown_netns.sh")
		teardownCmd.Dir = rootDir
		_ = teardownCmd.Run()
	}()

	// 1. Verify connectivity before loading cgroup block policy
	pingBefore := exec.Command("sudo", "ip", "netns", "exec", "client", "ping", "-c", "2", "-W", "1", "10.0.0.2")
	if out, err := pingBefore.CombinedOutput(); err != nil {
		t.Fatalf("Initial ping failed before loading cgroup policy: %s: %v", string(out), err)
	}
	t.Logf("[PASS] Baseline connectivity verified: 10.0.0.1 -> 10.0.0.2")

	// 2. Start firewall-agent in server netns, blocking cgroup /sys/fs/cgroup/test-app-blocked
	blockedCgroup := "/sys/fs/cgroup/test-app-blocked"
	agentCmd := exec.Command("sudo", "ip", "netns", "exec", "server", "./bin/firewall-agent", "--iface", "veth-s", "--block-cgroup", blockedCgroup)
	agentCmd.Dir = rootDir
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("Failed to start firewall agent: %v", err)
	}
	defer func() {
		if agentCmd.Process != nil {
			_ = agentCmd.Process.Kill()
		}
	}()

	// Wait for agent attachment
	time.Sleep(2 * time.Second)

	// 3. Test ping executed under test-app-allowed cgroup (Expect PASS)
	allowedPing := exec.Command("sudo", "sh", "-c", "echo $$ > /sys/fs/cgroup/test-app-allowed/cgroup.procs && ip netns exec client ping -c 2 -W 1 10.0.0.2")
	allowedOut, allowedErr := allowedPing.CombinedOutput()
	t.Logf("Ping output under allowed cgroup:\n%s", string(allowedOut))
	if allowedErr != nil {
		t.Fatalf("Ping under allowed cgroup failed unexpectedly: %s: %v", string(allowedOut), allowedErr)
	}
	t.Logf("[PASS] Traffic originating from allowed cgroup passed successfully!")

	// 4. Test ping executed under test-app-blocked cgroup (Expect XDP DROP / 100% loss)
	blockedPing := exec.Command("sudo", "sh", "-c", "echo $$ > /sys/fs/cgroup/test-app-blocked/cgroup.procs && ip netns exec client ping -c 3 -W 1 10.0.0.2")
	blockedOut, blockedErr := blockedPing.CombinedOutput()
	t.Logf("Ping output under blocked cgroup:\n%s", string(blockedOut))

	if blockedErr == nil {
		t.Fatalf("ERROR: Traffic originating from blocked cgroup succeeded, but expected XDP DROP!")
	}

	if strings.Contains(string(blockedOut), "100% packet loss") || strings.Contains(string(blockedOut), "100.0% packet loss") || blockedErr != nil {
		t.Logf("[SUCCESS] Phase 3 Cgroup Identity Resolution correctly dropped 100%% of traffic originating from %s!", blockedCgroup)
	}
}
