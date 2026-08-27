package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"policy_engine/pkg/identity"
	"policy_engine/pkg/observability"
)

// FirewallLoader manages loaded eBPF programs (XDP + TC), link attachments, and map operations.
type FirewallLoader struct {
	ifaceName      string
	iface          *net.Interface
	objs           xdpObjects
	tcObjs         tcObjects
	xdpLink        link.Link
	tcPinPath      string
	ringReader     *ringbuf.Reader
	cgroupResolver *identity.CgroupResolver
	mu             sync.RWMutex
}

// NewFirewallLoader initializes environment memory limits, loads eBPF objects, and attaches XDP & TC programs.
func NewFirewallLoader(ifaceName string) (*FirewallLoader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find network interface %s: %w", ifaceName, err)
	}

	loader := &FirewallLoader{
		ifaceName:      ifaceName,
		iface:          iface,
		cgroupResolver: identity.NewCgroupResolver(),
		tcPinPath:      fmt.Sprintf("/sys/fs/bpf/tc_fw_%s", ifaceName),
	}

	// 1. Ensure cgroup2 filesystem is mounted at /sys/fs/cgroup inside netns
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.procs"); err != nil {
		exec.Command("mount", "-t", "cgroup2", "none", "/sys/fs/cgroup").Run()
	}

	// 2. Load XDP eBPF programs & maps
	if err := loadXdpObjects(&loader.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load XDP objects: %w", err)
	}

	// Attach XDP program to network interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   loader.objs.XdpFirewallFunc,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   loader.objs.XdpFirewallFunc,
			Interface: iface.Index,
		})
		if err != nil {
			loader.objs.Close()
			return nil, fmt.Errorf("failed to attach XDP program to %s: %w", ifaceName, err)
		}
	}
	loader.xdpLink = l

	// 3. Load TC eBPF stateful conntrack programs & maps
	if err := loadTcObjects(&loader.tcObjs, nil); err != nil {
		l.Close()
		loader.objs.Close()
		return nil, fmt.Errorf("failed to load TC conntrack objects: %w", err)
	}

	// Mount BPF filesystem if not already mounted
	os.MkdirAll("/sys/fs/bpf", 0755)
	exec.Command("mount", "-t", "bpf", "bpffs", "/sys/fs/bpf").Run()

	// Provision clsact qdisc & attach pinned TC BPF filter
	os.Remove(loader.tcPinPath)
	if err := loader.tcObjs.TcFirewallFunc.Pin(loader.tcPinPath); err != nil {
		fmt.Printf("[!] Warning: Could not pin TC program to %s: %v\n", loader.tcPinPath, err)
	}

	exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact").Run()
	
	tcCmd := exec.Command("tc", "filter", "add", "dev", ifaceName, "ingress", "bpf", "da", "object-pinned", loader.tcPinPath)
	if out, err := tcCmd.CombinedOutput(); err != nil {
		exec.Command("tc", "filter", "add", "dev", ifaceName, "ingress", "bpf", "da", "obj", "pkg/bpf/tc_bpf.o", "sec", "tc").Run()
		_ = out
	}

	// 4. Initialize ring buffer reader for verdict audit events
	reader, err := ringbuf.NewReader(loader.objs.AuditRingbuf)
	if err != nil {
		l.Close()
		loader.tcObjs.Close()
		loader.objs.Close()
		return nil, fmt.Errorf("failed to create ringbuf reader: %w", err)
	}
	loader.ringReader = reader

	return loader, nil
}

// AddBlockCIDR inserts an IPv4 CIDR block rule into the LPM trie map for active generation.
func (l *FirewallLoader) AddBlockCIDR(cidrStr string, ruleID uint32) error {
	gen, _ := l.GetActiveGeneration()
	return l.StageCIDRRule(gen, cidrStr, ruleID, "deny")
}

// RemoveBlockCIDR removes an IPv4 CIDR block rule from the LPM trie map for active generation.
func (l *FirewallLoader) RemoveBlockCIDR(cidrStr string) error {
	gen, _ := l.GetActiveGeneration()
	l.mu.Lock()
	defer l.mu.Unlock()

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		ip := net.ParseIP(cidrStr)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid CIDR or IPv4 address: %s", cidrStr)
		}
		_, ipNet, _ = net.ParseCIDR(cidrStr + "/32")
	}

	ip4 := ipNet.IP.To4()
	prefixLen, _ := ipNet.Mask.Size()
	addrUint := binary.LittleEndian.Uint32(ip4)

	key := xdpLpmKeyIpv4{
		Prefixlen: uint32(32 + prefixLen),
		Gen:       gen,
		Addr:      addrUint,
	}

	if err := l.objs.LpmBlocklist.Delete(&key); err != nil {
		return fmt.Errorf("failed to delete CIDR %s from BPF LPM blocklist: %w", cidrStr, err)
	}

	return nil
}

// AddCgroupIdentity inserts a cgroup v2 numeric ID mapping into cgroup_identity_map for active generation.
func (l *FirewallLoader) AddCgroupIdentity(cgroupID uint64, identityID uint32) error {
	gen, _ := l.GetActiveGeneration()
	l.mu.Lock()
	defer l.mu.Unlock()

	key := xdpCgroupKey{
		Gen:      gen,
		Pad:      0,
		CgroupId: cgroupID,
	}

	if err := l.objs.CgroupIdentityMap.Put(&key, &identityID); err != nil {
		return fmt.Errorf("failed to insert cgroup_id %d into cgroup_identity_map: %w", cgroupID, err)
	}
	return nil
}

// RemoveCgroupIdentity removes a cgroup v2 numeric ID mapping from cgroup_identity_map for active generation.
func (l *FirewallLoader) RemoveCgroupIdentity(cgroupID uint64) error {
	gen, _ := l.GetActiveGeneration()
	l.mu.Lock()
	defer l.mu.Unlock()

	key := xdpCgroupKey{
		Gen:      gen,
		Pad:      0,
		CgroupId: cgroupID,
	}

	if err := l.objs.CgroupIdentityMap.Delete(&key); err != nil {
		return fmt.Errorf("failed to delete cgroup_id %d from cgroup_identity_map: %w", cgroupID, err)
	}
	return nil
}

// AddCgroupPathBlock resolves a cgroup directory path to its inode ID and inserts it into cgroup_identity_map for active generation.
func (l *FirewallLoader) AddCgroupPathBlock(cgroupPath string, identityID uint32) error {
	gen, _ := l.GetActiveGeneration()
	return l.StageCgroupRule(gen, cgroupPath, identityID, "deny")
}

// GetActiveGeneration returns the active policy generation index from kernel BPF array map.
func (l *FirewallLoader) GetActiveGeneration() (uint32, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var key uint32 = 0
	var gen uint32
	if err := l.objs.ActiveGenerationMap.Lookup(&key, &gen); err != nil {
		return 0, nil
	}
	return gen, nil
}

// SetActiveGeneration updates the active policy generation index in kernel BPF array map.
func (l *FirewallLoader) SetActiveGeneration(gen uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var key uint32 = 0
	if err := l.objs.ActiveGenerationMap.Put(&key, &gen); err != nil {
		return fmt.Errorf("failed to update active_generation_map to %d: %w", gen, err)
	}
	return nil
}

// StageCIDRRule inserts a generation-indexed CIDR rule into BPF LPM blocklist.
func (l *FirewallLoader) StageCIDRRule(gen uint32, cidrStr string, ruleID uint32, action string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		ip := net.ParseIP(cidrStr)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid CIDR or IPv4 address: %s", cidrStr)
		}
		_, ipNet, _ = net.ParseCIDR(cidrStr + "/32")
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported: %s", cidrStr)
	}

	prefixLen, _ := ipNet.Mask.Size()
	addrUint := binary.LittleEndian.Uint32(ip4)

	key := xdpLpmKeyIpv4{
		Prefixlen: uint32(32 + prefixLen),
		Gen:       gen,
		Addr:      addrUint,
	}

	if err := l.objs.LpmBlocklist.Put(&key, &ruleID); err != nil {
		return fmt.Errorf("failed to stage CIDR %s (gen %d): %w", cidrStr, gen, err)
	}
	return nil
}

// StageCgroupRule resolves a cgroup path and inserts a generation-indexed cgroup rule.
func (l *FirewallLoader) StageCgroupRule(gen uint32, cgroupPath string, ruleID uint32, action string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	cgroupID, err := l.cgroupResolver.GetCgroupID(cgroupPath)
	if err != nil {
		return fmt.Errorf("failed to resolve cgroup path %s: %w", cgroupPath, err)
	}

	key := xdpCgroupKey{
		Gen:      gen,
		Pad:      0,
		CgroupId: cgroupID,
	}

	if err := l.objs.CgroupIdentityMap.Put(&key, &ruleID); err != nil {
		return fmt.Errorf("failed to stage cgroup %s (gen %d): %w", cgroupPath, gen, err)
	}
	return nil
}

// StagePortRule inserts a generation-indexed port/protocol rule into BPF PortRulesMap.
func (l *FirewallLoader) StagePortRule(gen uint32, port uint16, protocol string, ruleID uint32, action string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var protoVal uint8 = 6 // TCP
	switch strings.ToLower(protocol) {
	case "tcp":
		protoVal = 6
	case "udp":
		protoVal = 17
	case "icmp":
		protoVal = 1
	}

	var actVal uint32 = 2 // ACTION_DENY = 2
	if strings.ToLower(action) == "allow" {
		actVal = 1 // ACTION_ALLOW = 1
	}

	key := xdpPortRuleKey{
		Gen:      gen,
		DstPort:  port,
		Protocol: protoVal,
		Pad:      0,
	}

	val := xdpPortRuleVal{
		Action: actVal,
		RuleId: ruleID,
	}

	if err := l.objs.PortRulesMap.Put(&key, &val); err != nil {
		return fmt.Errorf("failed to stage port rule %d/%s (gen %d): %w", port, protocol, gen, err)
	}
	return nil
}

// ClearGenerationRules purges all BPF map rules associated with a specific generation index.
func (l *FirewallLoader) ClearGenerationRules(gen uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Clear LpmBlocklist keys
	var lpmKeysToDelete []xdpLpmKeyIpv4
	var lpmKey xdpLpmKeyIpv4
	var ruleID uint32
	iterLpm := l.objs.LpmBlocklist.Iterate()
	for iterLpm.Next(&lpmKey, &ruleID) {
		if lpmKey.Gen == gen {
			lpmKeysToDelete = append(lpmKeysToDelete, lpmKey)
		}
	}
	for _, k := range lpmKeysToDelete {
		_ = l.objs.LpmBlocklist.Delete(&k)
	}

	// Clear CgroupIdentityMap keys
	var cgKeysToDelete []xdpCgroupKey
	var cgKey xdpCgroupKey
	iterCg := l.objs.CgroupIdentityMap.Iterate()
	for iterCg.Next(&cgKey, &ruleID) {
		if cgKey.Gen == gen {
			cgKeysToDelete = append(cgKeysToDelete, cgKey)
		}
	}
	for _, k := range cgKeysToDelete {
		_ = l.objs.CgroupIdentityMap.Delete(&k)
	}

	// Clear PortRulesMap keys
	var portKeysToDelete []xdpPortRuleKey
	var portKey xdpPortRuleKey
	var portVal xdpPortRuleVal
	iterPort := l.objs.PortRulesMap.Iterate()
	for iterPort.Next(&portKey, &portVal) {
		if portKey.Gen == gen {
			portKeysToDelete = append(portKeysToDelete, portKey)
		}
	}
	for _, k := range portKeysToDelete {
		_ = l.objs.PortRulesMap.Delete(&k)
	}

	return nil
}


// ConntrackFlow represents an active 5-tuple connection flow query result.
type ConntrackFlow struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	State    uint32
	Packets  uint64
	Bytes    uint64
}

// GetConntrackFlows queries active connection flows from the kernel conntrack LRU map.
func (l *FirewallLoader) GetConntrackFlows() ([]ConntrackFlow, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var flows []ConntrackFlow
	var key tcFlowKey
	var val tcFlowState

	iter := l.tcObjs.ConntrackMap.Iterate()
	for iter.Next(&key, &val) {
		src := intToIP(key.SrcIp)
		dst := intToIP(key.DstIp)
		flows = append(flows, ConntrackFlow{
			SrcIP:    src,
			DstIP:    dst,
			SrcPort:  key.SrcPort,
			DstPort:  key.DstPort,
			Protocol: key.Protocol,
			State:    val.State,
			Packets:  val.Packets,
			Bytes:    val.Bytes,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("conntrack map iteration error: %w", err)
	}
	return flows, nil
}

func intToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(nn)
	ip[1] = byte(nn >> 8)
	ip[2] = byte(nn >> 16)
	ip[3] = byte(nn >> 24)
	return ip
}

// Stats represents aggregated packet statistics across all CPUs.
type Stats struct {
	RxPackets   uint64
	RxBytes     uint64
	PassPackets uint64
	DropPackets uint64
}

// GetStats queries and aggregates per-CPU packet statistics from xdp_stats_map and tc_stats_map.
func (l *FirewallLoader) GetStats() (Stats, error) {
	var total Stats
	var perCPU []xdpStatsValue

	var key uint32 = 0
	if err := l.objs.XdpStatsMap.Lookup(&key, &perCPU); err == nil {
		for _, cpuStats := range perCPU {
			total.RxPackets += cpuStats.RxPackets
			total.RxBytes += cpuStats.RxBytes
			total.PassPackets += cpuStats.PassPackets
			total.DropPackets += cpuStats.DropPackets
		}
	}

	var tcPerCPU []tcStatsValue
	if err := l.tcObjs.TcStatsMap.Lookup(&key, &tcPerCPU); err == nil {
		for _, cpuStats := range tcPerCPU {
			total.RxPackets += cpuStats.RxPackets
			total.RxBytes += cpuStats.RxBytes
			total.PassPackets += cpuStats.PassPackets
			total.DropPackets += cpuStats.DropPackets
		}
	}

	return total, nil
}

// ReadRingbuf streams verdict events from the kernel ring buffer.
func (l *FirewallLoader) ReadRingbuf(ctx context.Context, handler func(observability.AuditEvent)) error {
	go func() {
		<-ctx.Done()
		if l.ringReader != nil {
			l.ringReader.Close()
		}
	}()

	for {
		record, err := l.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("ringbuf read error: %w", err)
		}

		var event observability.AuditEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		handler(event)
	}
}

// Close detaches XDP & TC links, closes ringbuf reader, and unloads BPF objects.
func (l *FirewallLoader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.ringReader != nil {
		l.ringReader.Close()
	}
	if l.xdpLink != nil {
		l.xdpLink.Close()
	}
	// Clean up clsact qdisc and pinned BPF object
	exec.Command("tc", "qdisc", "del", "dev", l.ifaceName, "clsact").Run()
	if l.tcPinPath != "" {
		os.Remove(l.tcPinPath)
	}

	l.tcObjs.Close()
	return l.objs.Close()
}
