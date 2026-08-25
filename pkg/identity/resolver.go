package identity

import "context"

// IdentityResolver defines the common interface for pluggable identity backends.
type IdentityResolver interface {
	// ResolveID maps a kernel identifier (cgroup_id, socket_cookie, etc) to a security identity ID.
	ResolveID(ctx context.Context, key uint64) (uint32, error)
	// Name returns the identifier of the identity backend.
	Name() string
}
