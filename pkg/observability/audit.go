package observability

import (
	"sync"
)

// AuditStore keeps an in-memory queryable history of audit events.
type AuditStore struct {
	mu     sync.RWMutex
	events []AuditEvent
}

func NewAuditStore() *AuditStore {
	return &AuditStore{
		events: make([]AuditEvent, 0, 1024),
	}
}

func (s *AuditStore) Add(event AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *AuditStore) Events() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]AuditEvent, len(s.events))
	copy(res, s.events)
	return res
}
