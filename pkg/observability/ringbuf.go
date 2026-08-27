package observability

import (
	"context"
	"fmt"
	"net"
	"time"
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

func (e *AuditEvent) FormattedSrcIP() string {
	return intToIP(e.SrcIP).String()
}

func (e *AuditEvent) FormattedDstIP() string {
	return intToIP(e.DstIP).String()
}

func (e *AuditEvent) VerdictString() string {
	switch e.Verdict {
	case 0:
		return "PASS"
	case 1:
		return "DROP"
	case 2:
		return "REDIRECT"
	default:
		return "UNKNOWN"
	}
}

func (e *AuditEvent) ReasonString() string {
	switch e.ReasonCode {
	case 0:
		return "OK"
	case 1:
		return "CIDR_BLOCKED"
	case 2:
		return "PORT_BLOCKED"
	case 3:
		return "INVALID_TCP_FLAGS"
	case 4:
		return "IDENTITY_DENY"
	case 5:
		return "UNTRACKED_NON_SYN"
	case 6:
		return "DEFAULT_DROP"
	default:
		return fmt.Sprintf("REASON_%d", e.ReasonCode)
	}
}

func (e *AuditEvent) ProtocolString() string {
	switch e.Protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO_%d", e.Protocol)
	}
}

func (e *AuditEvent) TimestampFormatted() string {
	if e.TimestampNS == 0 {
		return time.Now().Format("15:04:05.000")
	}
	// Convert kernel timestamp to readable time string
	sec := int64(e.TimestampNS / 1e9)
	nsec := int64(e.TimestampNS % 1e9)
	return time.Unix(sec, nsec).Format("15:04:05.000")
}

func (e *AuditEvent) String() string {
	return fmt.Sprintf("[%s] %s:%d -> %s:%d (%s) Reason=%s RuleID=%d CgroupID=%d IdentityID=%d",
		e.VerdictString(), e.FormattedSrcIP(), e.SrcPort, e.FormattedDstIP(), e.DstPort, e.ProtocolString(), e.ReasonString(), e.RuleID, e.CgroupID, e.IdentityID)
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

