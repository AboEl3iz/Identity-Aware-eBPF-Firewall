package observability

import (
	"context"
	"fmt"
	"net"
)

// AuditEvent mirrors struct audit_event in bpf/headers/common.h
type AuditEvent struct {
	TimestampNS uint64
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	Verdict     uint8
	ReasonCode  uint16
	RuleID      uint32
	CgroupID    uint64
	IdentityID  uint32
}

func (e *AuditEvent) String() string {
	src := intToIP(e.SrcIP)
	dst := intToIP(e.DstIP)
	verdictStr := "PASS"
	if e.Verdict == 1 {
		verdictStr = "DROP"
	}
	return fmt.Sprintf("[%s] %s:%d -> %s:%d (Proto %d) Reason=%d RuleID=%d CgroupID=%d IdentityID=%d",
		verdictStr, src, e.SrcPort, dst, e.DstPort, e.Protocol, e.ReasonCode, e.RuleID, e.CgroupID, e.IdentityID)
}

func intToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(nn)
	ip[1] = byte(nn >> 8)
	ip[2] = byte(nn >> 16)
	ip[3] = byte(nn >> 24)
	return ip
}

// RingbufConsumer consumes eBPF ring buffer verdict events.
type RingbufConsumer struct{}

func NewRingbufConsumer() *RingbufConsumer {
	return &RingbufConsumer{}
}

func (c *RingbufConsumer) Start(ctx context.Context, handler func(AuditEvent)) error {
	<-ctx.Done()
	return nil
}
