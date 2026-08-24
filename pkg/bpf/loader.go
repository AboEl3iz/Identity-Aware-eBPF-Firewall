package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"policy_engine/pkg/observability"
)

// FirewallLoader manages loaded eBPF programs, link attachments, and map operations.
type FirewallLoader struct {
	ifaceName  string
	iface      *net.Interface
	objs       xdpObjects
	xdpLink    link.Link
	ringReader *ringbuf.Reader
	mu         sync.RWMutex
}

// NewFirewallLoader initializes environment memory limits, loads eBPF objects, and attaches XDP program.
func NewFirewallLoader(ifaceName string) (*FirewallLoader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find network interface %s: %w", ifaceName, err)
	}

	loader := &FirewallLoader{
		ifaceName: ifaceName,
		iface:     iface,
	}

	// Load eBPF programs and maps into kernel
	if err := loadXdpObjects(&loader.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load XDP objects: %w", err)
	}

	// Attach XDP program to network interface (Generic mode works on veth and all drivers)
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   loader.objs.XdpFirewallFunc,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		// Fallback to default mode
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

	// Initialize ring buffer reader for verdict audit events
	reader, err := ringbuf.NewReader(loader.objs.AuditRingbuf)
	if err != nil {
		l.Close()
		loader.objs.Close()
		return nil, fmt.Errorf("failed to create ringbuf reader: %w", err)
	}
	loader.ringReader = reader

	return loader, nil
}

// AddBlockCIDR inserts an IPv4 CIDR block rule into the LPM trie map.
func (l *FirewallLoader) AddBlockCIDR(cidrStr string, ruleID uint32) error {
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
	// Use LittleEndian so that in memory on x86, byte 0 is ip4[0] (matching iph->saddr byte order)
	addrUint := binary.LittleEndian.Uint32(ip4)

	key := xdpLpmKeyIpv4{
		Prefixlen: uint32(prefixLen),
		Addr:      addrUint,
	}

	if err := l.objs.LpmBlocklist.Put(&key, &ruleID); err != nil {
		return fmt.Errorf("failed to insert CIDR %s into BPF LPM blocklist: %w", cidrStr, err)
	}

	return nil
}

// RemoveBlockCIDR removes an IPv4 CIDR block rule from the LPM trie map.
func (l *FirewallLoader) RemoveBlockCIDR(cidrStr string) error {
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
		Prefixlen: uint32(prefixLen),
		Addr:      addrUint,
	}

	if err := l.objs.LpmBlocklist.Delete(&key); err != nil {
		return fmt.Errorf("failed to delete CIDR %s from BPF LPM blocklist: %w", cidrStr, err)
	}

	return nil
}

// Stats represents aggregated packet statistics across all CPUs.
type Stats struct {
	RxPackets   uint64
	RxBytes     uint64
	PassPackets uint64
	DropPackets uint64
}

// GetStats queries and aggregates per-CPU packet statistics from xdp_stats_map.
func (l *FirewallLoader) GetStats() (Stats, error) {
	var total Stats
	var perCPU []xdpStatsValue

	var key uint32 = 0
	if err := l.objs.XdpStatsMap.Lookup(&key, &perCPU); err != nil {
		return total, fmt.Errorf("failed to lookup stats map: %w", err)
	}

	for _, cpuStats := range perCPU {
		total.RxPackets += cpuStats.RxPackets
		total.RxBytes += cpuStats.RxBytes
		total.PassPackets += cpuStats.PassPackets
		total.DropPackets += cpuStats.DropPackets
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

// Close detaches XDP links, closes ringbuf reader, and unloads BPF objects.
func (l *FirewallLoader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.ringReader != nil {
		l.ringReader.Close()
	}
	if l.xdpLink != nil {
		l.xdpLink.Close()
	}
	return l.objs.Close()
}
