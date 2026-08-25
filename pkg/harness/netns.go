package harness

import (
	"fmt"
	"os/exec"
)

// NetnsManager handles creation and teardown of veth-paired network namespaces.
type NetnsManager struct {
	ClientNS string
	ServerNS string
	VethC    string
	VethS    string
	ClientIP string
	ServerIP string
}

func NewNetnsManager(clientNS, serverNS, vethC, vethS, clientIP, serverIP string) *NetnsManager {
	return &NetnsManager{
		ClientNS: clientNS,
		ServerNS: serverNS,
		VethC:    vethC,
		VethS:    vethS,
		ClientIP: clientIP,
		ServerIP: serverIP,
	}
}

// Setup provisions the client and server namespaces linked via a veth pair.
func (m *NetnsManager) Setup() error {
	cmd := exec.Command("sudo", "./scripts/setup_netns.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("setup_netns.sh failed: %s: %w", string(out), err)
	}
	return nil
}

// Teardown cleans up the client and server network namespaces.
func (m *NetnsManager) Teardown() error {
	cmd := exec.Command("sudo", "./scripts/teardown_netns.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("teardown_netns.sh failed: %s: %w", string(out), err)
	}
	return nil
}
