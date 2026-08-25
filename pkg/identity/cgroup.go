package identity

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

// CgroupResolver resolves cgroup v2 paths and numeric IDs (inode numbers) to security identity IDs.
type CgroupResolver struct{}

func NewCgroupResolver() *CgroupResolver {
	return &CgroupResolver{}
}

// GetCgroupID returns the 64-bit cgroup v2 ID (filesystem inode number) for a given cgroup directory path.
func (r *CgroupResolver) GetCgroupID(cgroupPath string) (uint64, error) {
	fi, err := os.Stat(cgroupPath)
	if err != nil {
		return 0, fmt.Errorf("failed to stat cgroup path %s: %w", cgroupPath, err)
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("failed to get raw syscall.Stat_t for cgroup path %s", cgroupPath)
	}

	return stat.Ino, nil
}

func (r *CgroupResolver) ResolveID(ctx context.Context, cgroupID uint64) (uint32, error) {
	return uint32(cgroupID % 10000), nil
}

func (r *CgroupResolver) Name() string {
	return "cgroupv2"
}
