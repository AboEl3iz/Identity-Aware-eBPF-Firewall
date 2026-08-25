package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func findRootDir(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("Could not find project root containing go.mod")
		}
		dir = parent
	}
}

func TestPhase1StatelessXDPDrop(t *testing.T) {
	rootDir := findRootDir(t)

	// Provision network namespaces
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

	// 1. Verify connectivity before policy load (client -> server)
	pingBefore := exec.Command("sudo", "ip", "netns", "exec", "client", "ping", "-c", "2", "-W", "1", "10.0.0.2")
	if out, err := pingBefore.CombinedOutput(); err != nil {
		t.Fatalf("Initial ping failed before loading firewall policy: %s: %v", string(out), err)
	}
	t.Logf("[PASS] Baseline connectivity verified: client (10.0.0.1) -> server (10.0.0.2)")

	// 2. Start firewall-agent in background inside server netns, blocking 10.0.0.1/32
	agentCmd := exec.Command("sudo", "ip", "netns", "exec", "server", "./bin/firewall-agent", "--iface", "veth-s", "--block-cidr", "10.0.0.1/32")
	agentCmd.Dir = rootDir
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("Failed to start firewall agent: %v", err)
	}
	defer func() {
		if agentCmd.Process != nil {
			_ = agentCmd.Process.Kill()
		}
	}()

	// Wait for XDP program to attach
	time.Sleep(2 * time.Second)

	// 3. Test blocked CIDR (client -> server ping must be DROPPED by XDP)
	pingBlocked := exec.Command("sudo", "ip", "netns", "exec", "client", "ping", "-c", "3", "-W", "1", "10.0.0.2")
	out, err := pingBlocked.CombinedOutput()
	t.Logf("Ping output under blocked policy:\n%s", string(out))

	if err == nil {
		t.Fatalf("ERROR: Ping succeeded but expected XDP DROP for blocked CIDR 10.0.0.1/32!")
	}

	if strings.Contains(string(out), "100% packet loss") || strings.Contains(string(out), "100.0% packet loss") || err != nil {
		t.Logf("[SUCCESS] Phase 1 XDP Volumetric Dropper correctly dropped 100%% of packets for 10.0.0.1/32!")
	}
}
