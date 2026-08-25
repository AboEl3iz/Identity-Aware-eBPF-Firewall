package e2e

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestStatefulConntrack(t *testing.T) {
	rootDir := findRootDir(t)

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

	// 1. Start TCP listener in server netns
	serverListener := exec.Command("sudo", "ip", "netns", "exec", "server", "nc", "-l", "-k", "-p", "8080")
	if err := serverListener.Start(); err != nil {
		t.Fatalf("Failed to start TCP listener on server: %v", err)
	}
	defer func() {
		if serverListener.Process != nil {
			_ = serverListener.Process.Kill()
		}
	}()

	// 2. Start firewall-agent in server netns attached to veth-s
	agentCmd := exec.Command("sudo", "ip", "netns", "exec", "server", "./bin/firewall-agent", "--iface", "veth-s")
	agentCmd.Dir = rootDir
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("Failed to start firewall agent: %v", err)
	}
	defer func() {
		if agentCmd.Process != nil {
			_ = agentCmd.Process.Kill()
		}
	}()

	// Wait for agent and TC classifier attachment
	time.Sleep(2 * time.Second)

	// 3. Initiate valid TCP stream from client to server port 8080 (SYN -> SYN-ACK -> ACK)
	clientConn := exec.Command("sudo", "ip", "netns", "exec", "client", "nc", "-z", "-v", "-w", "2", "10.0.0.2", "8080")
	out, err := clientConn.CombinedOutput()
	t.Logf("TCP handshake attempt output:\n%s", string(out))

	if err != nil && !strings.Contains(string(out), "succeeded") && !strings.Contains(string(out), "open") {
		t.Fatalf("Valid TCP connection attempt failed unexpectedly: %s: %v", string(out), err)
	}
	t.Logf("[SUCCESS] Valid TCP SYN handshake and connection established cleanly!")
}
