package e2e

import (
	"testing"

	"policy_engine/pkg/observability"
)

func TestAuditStoreCircularBuffer(t *testing.T) {
	store := observability.NewAuditStore(5) // Max capacity 5

	for i := 1; i <= 10; i++ {
		store.Add(observability.AuditEvent{
			RuleID:     uint32(i),
			ReasonCode: uint16(i % 5),
			Verdict:    uint8(i % 2),
		})
	}

	if store.Count() != 5 {
		t.Fatalf("Expected AuditStore count to be 5 (capacity limit), got %d", store.Count())
	}

	events := store.Events()
	if events[0].RuleID != 6 {
		t.Errorf("Expected oldest remaining rule ID to be 6 after eviction, got %d", events[0].RuleID)
	}
	if events[4].RuleID != 10 {
		t.Errorf("Expected newest rule ID to be 10, got %d", events[4].RuleID)
	}

	t.Logf("[PASS] AuditStore circular ring buffer eviction & capacity verified!")
}

func TestAuditEventFormatting(t *testing.T) {
	evt := observability.AuditEvent{
		SrcIP:      0x0200000A, // 10.0.0.2 in Little Endian
		DstIP:      0x0100000A, // 10.0.0.1 in Little Endian
		SrcPort:    54321,
		DstPort:    8080,
		Protocol:   6, // TCP
		Verdict:    1, // DROP
		ReasonCode: 2, // PORT_BLOCKED
		RuleID:     201,
	}

	if evt.VerdictString() != "DROP" {
		t.Errorf("Expected VerdictString 'DROP', got '%s'", evt.VerdictString())
	}
	if evt.ReasonString() != "PORT_BLOCKED" {
		t.Errorf("Expected ReasonString 'PORT_BLOCKED', got '%s'", evt.ReasonString())
	}
	if evt.ProtocolString() != "TCP" {
		t.Errorf("Expected ProtocolString 'TCP', got '%s'", evt.ProtocolString())
	}

	formatted := evt.String()
	if formatted == "" {
		t.Errorf("Expected non-empty string representation for AuditEvent")
	}

	t.Logf("[PASS] AuditEvent explainability formatting verified: %s", formatted)
}

func TestAuditStoreFiltering(t *testing.T) {
	store := observability.NewAuditStore(100)

	store.Add(observability.AuditEvent{Verdict: 0, RuleID: 101, ReasonCode: 0}) // PASS
	store.Add(observability.AuditEvent{Verdict: 1, RuleID: 201, ReasonCode: 2}) // DROP (PORT_BLOCKED)
	store.Add(observability.AuditEvent{Verdict: 1, RuleID: 301, ReasonCode: 4}) // DROP (IDENTITY_DENY)

	drops := store.Filter("DROP", "")
	if len(drops) != 2 {
		t.Errorf("Expected 2 DROP events, got %d", len(drops))
	}

	portDrops := store.Filter("DROP", "PORT_BLOCKED")
	if len(portDrops) != 1 {
		t.Errorf("Expected 1 PORT_BLOCKED drop event, got %d", len(portDrops))
	}

	t.Logf("[PASS] AuditStore filtering engine verified!")
}
