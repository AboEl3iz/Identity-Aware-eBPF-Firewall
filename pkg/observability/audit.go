package observability

import (
	"strings"
	"sync"
)

// AuditStore keeps an in-memory queryable history of audit events with fixed capacity ring buffer semantics.
type AuditStore struct {
	mu       sync.RWMutex
	capacity int
	events   []AuditEvent
}

func NewAuditStore(capacity int) *AuditStore {
	if capacity <= 0 {
		capacity = 1000
	}
	return &AuditStore{
		capacity: capacity,
		events:   make([]AuditEvent, 0, capacity),
	}
}

func (s *AuditStore) Add(event AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.events) >= s.capacity {
		// Evict oldest element (head)
		s.events = s.events[1:]
	}
	s.events = append(s.events, event)
}

func (s *AuditStore) Events() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]AuditEvent, len(s.events))
	copy(res, s.events)
	return res
}

func (s *AuditStore) Filter(verdictFilter string, query string) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	vLower := strings.ToLower(strings.TrimSpace(verdictFilter))
	qLower := strings.ToLower(strings.TrimSpace(query))

	var filtered []AuditEvent
	for _, evt := range s.events {
		if vLower != "" && vLower != "all" {
			if strings.ToLower(evt.VerdictString()) != vLower {
				continue
			}
		}

		if qLower != "" {
			fullStr := strings.ToLower(evt.String())
			if !strings.Contains(fullStr, qLower) {
				continue
			}
		}

		filtered = append(filtered, evt)
	}

	return filtered
}

func (s *AuditStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

func (s *AuditStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = s.events[:0]
}

