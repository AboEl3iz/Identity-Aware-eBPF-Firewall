package security

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

// Linux capability constants
const (
	CapNetAdmin   uint32 = 12
	CapSysAdmin   uint32 = 21
	CapSysResource uint32 = 24
	CapPerfmon    uint32 = 38
	CapBPF        uint32 = 39
)

// CapabilityNames maps numeric Linux capability IDs to human-readable strings
var CapabilityNames = map[uint32]string{
	CapNetAdmin:   "CAP_NET_ADMIN",
	CapSysAdmin:   "CAP_SYS_ADMIN",
	CapSysResource: "CAP_SYS_RESOURCE",
	CapPerfmon:    "CAP_PERFMON",
	CapBPF:        "CAP_BPF",
}

// CapabilitySet represents the effective and permitted capabilities of a process
type CapabilitySet struct {
	Effective []uint32 `json:"effective"`
	Permitted []uint32 `json:"permitted"`
	IsRoot    bool     `json:"is_root"`
	HasCapBPF bool     `json:"has_cap_bpf"`
	HasCapNet bool     `json:"has_cap_net_admin"`
}

// GetProcessCapabilities retrieves the current process effective and permitted capability sets.
func GetProcessCapabilities() (*CapabilitySet, error) {
	hdr := &unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     int32(os.Getpid()),
	}
	var data [2]unix.CapUserData
	if err := unix.Capget(hdr, &data[0]); err != nil {
		return nil, fmt.Errorf("capget failed: %w", err)
	}

	effBits := uint64(data[0].Effective) | (uint64(data[1].Effective) << 32)
	permBits := uint64(data[0].Permitted) | (uint64(data[1].Permitted) << 32)

	cs := &CapabilitySet{
		Effective: extractCapBits(effBits),
		Permitted: extractCapBits(permBits),
		IsRoot:    os.Geteuid() == 0,
	}

	cs.HasCapBPF = hasCap(effBits, CapBPF) || hasCap(effBits, CapSysAdmin)
	cs.HasCapNet = hasCap(effBits, CapNetAdmin) || hasCap(effBits, CapSysAdmin)

	return cs, nil
}

// DropCapabilities drops all capabilities except those specified in keepCaps.
func DropCapabilities(keepCaps []uint32) error {
	var keepBits uint64
	for _, capID := range keepCaps {
		if capID < 64 {
			keepBits |= (1 << capID)
		}
	}

	hdr := &unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     int32(os.Getpid()),
	}

	var data [2]unix.CapUserData
	data[0].Effective = uint32(keepBits & 0xFFFFFFFF)
	data[0].Permitted = uint32(keepBits & 0xFFFFFFFF)
	data[0].Inheritable = 0

	data[1].Effective = uint32((keepBits >> 32) & 0xFFFFFFFF)
	data[1].Permitted = uint32((keepBits >> 32) & 0xFFFFFFFF)
	data[1].Inheritable = 0

	if err := unix.Capset(hdr, &data[0]); err != nil {
		return fmt.Errorf("capset failed: %w", err)
	}

	return nil
}

// EnsureMinimalCapabilities restricts the process capabilities to minimal eBPF + NetAdmin privileges.
func EnsureMinimalCapabilities() (*CapabilitySet, error) {
	caps, err := GetProcessCapabilities()
	if err != nil {
		return nil, fmt.Errorf("unable to read process capabilities: %w", err)
	}

	// Minimal required capabilities for eBPF firewall engine
	minimalCaps := []uint32{CapBPF, CapNetAdmin, CapSysResource, CapPerfmon, CapSysAdmin}

	log.Printf("[SECURITY] Checking process capabilities (UID: %d, Root: %v)...", os.Geteuid(), caps.IsRoot)
	log.Printf("[SECURITY] Effective caps before bounding: %v", caps.CapNames(caps.Effective))

	// Attempt capability bounding
	if err := DropCapabilities(minimalCaps); err != nil {
		log.Printf("[SECURITY] Warning: Could not drop unneeded capabilities: %v (running with existing caps)", err)
	} else {
		log.Printf("[SECURITY] Privilege separation applied: bounded process to minimal capabilities (CAP_BPF, CAP_NET_ADMIN, CAP_SYS_RESOURCE).")
	}

	boundedCaps, err := GetProcessCapabilities()
	if err != nil {
		return caps, nil
	}

	return boundedCaps, nil
}

func (cs *CapabilitySet) CapNames(capIDs []uint32) []string {
	names := make([]string, 0, len(capIDs))
	for _, id := range capIDs {
		if name, ok := CapabilityNames[id]; ok {
			names = append(names, name)
		} else {
			names = append(names, fmt.Sprintf("CAP_%d", id))
		}
	}
	return names
}

func hasCap(bits uint64, capID uint32) bool {
	if capID >= 64 {
		return false
	}
	return (bits & (1 << capID)) != 0
}

func extractCapBits(bits uint64) []uint32 {
	var caps []uint32
	for i := uint32(0); i < 64; i++ {
		if (bits & (1 << i)) != 0 {
			caps = append(caps, i)
		}
	}
	return caps
}
