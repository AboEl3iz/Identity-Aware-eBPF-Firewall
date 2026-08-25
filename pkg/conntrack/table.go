package conntrack

import (
	"fmt"
	"sync"
	"time"

	"policy_engine/pkg/bpf"
)

// FlowState tracks connection metrics and state in userspace.
type FlowState struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	State     string
	Packets   uint64
	Bytes     uint64
	LastSeen  time.Time
}

// Table manages userspace mirror of connection tracking table.
type Table struct {
	mu    sync.RWMutex
	flows map[string]*FlowState
}

func NewTable() *Table {
	return &Table{
		flows: make(map[string]*FlowState),
	}
}

// SyncFromKernel polls active conntrack flows from kernel loader and updates local map.
func (t *Table) SyncFromKernel(loader *bpf.FirewallLoader) ([]*FlowState, error) {
	kernelFlows, err := loader.GetConntrackFlows()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch kernel conntrack flows: %w", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	active := make([]*FlowState, 0, len(kernelFlows))
	now := time.Now()

	for _, kf := range kernelFlows {
		flowKey := fmt.Sprintf("%s:%d->%s:%d(%d)", kf.SrcIP, kf.SrcPort, kf.DstIP, kf.DstPort, kf.Protocol)
		
		stateStr := "SYN_SENT"
		if kf.State == 3 {
			stateStr = "ESTABLISHED"
		} else if kf.State == 5 {
			stateStr = "CLOSED"
		}

		fs := &FlowState{
			SrcIP:    kf.SrcIP.String(),
			DstIP:    kf.DstIP.String(),
			SrcPort:  kf.SrcPort,
			DstPort:  kf.DstPort,
			Protocol: kf.Protocol,
			State:    stateStr,
			Packets:  kf.Packets,
			Bytes:    kf.Bytes,
			LastSeen: now,
		}

		t.flows[flowKey] = fs
		active = append(active, fs)
	}

	return active, nil
}
