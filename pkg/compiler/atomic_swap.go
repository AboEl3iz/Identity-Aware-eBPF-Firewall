package compiler

import (
	"fmt"
	"sync"
)

// BPFStager defines the interface required by MapSwapper to stage and swap BPF map rules.
type BPFStager interface {
	GetActiveGeneration() (uint32, error)
	SetActiveGeneration(gen uint32) error
	StageCIDRRule(gen uint32, cidrStr string, ruleID uint32, action string) error
	StageCgroupRule(gen uint32, cgroupPath string, ruleID uint32, action string) error
	StagePortRule(gen uint32, port uint16, protocol string, ruleID uint32, action string) error
	ClearGenerationRules(gen uint32) error
}

// MapSwapper manages zero-drop generation-indexed atomic updates and automatic rollback.
type MapSwapper struct {
	mu sync.Mutex
}

func NewMapSwapper() *MapSwapper {
	return &MapSwapper{}
}

// ApplyPolicyAtomic stages a compiled policy under nextGen, atomically switches active generation, and purges old rules.
func (s *MapSwapper) ApplyPolicyAtomic(stager BPFStager, cp *CompiledPolicy) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	curGen, err := stager.GetActiveGeneration()
	if err != nil {
		return 0, fmt.Errorf("failed to get active generation: %w", err)
	}

	nextGen := curGen + 1

	// Ensure target generation slot is clean before staging
	_ = stager.ClearGenerationRules(nextGen)

	// 1. Stage CIDR rules
	for _, item := range cp.CIDRBlocks {
		if err := stager.StageCIDRRule(nextGen, item.CIDRStr, item.RuleID, item.Action); err != nil {
			_ = stager.ClearGenerationRules(nextGen) // Rollback nextGen staging
			return curGen, fmt.Errorf("staging failed for CIDR %s (Rule %d): %w", item.CIDRStr, item.RuleID, err)
		}
	}

	// 2. Stage Cgroup rules
	for _, item := range cp.CgroupBlocks {
		if err := stager.StageCgroupRule(nextGen, item.CgroupPath, item.RuleID, item.Action); err != nil {
			_ = stager.ClearGenerationRules(nextGen) // Rollback nextGen staging
			return curGen, fmt.Errorf("staging failed for Cgroup %s (Rule %d): %w", item.CgroupPath, item.RuleID, err)
		}
	}

	// 3. Stage Port rules
	for _, item := range cp.PortRules {
		if err := stager.StagePortRule(nextGen, item.DstPort, item.Protocol, item.RuleID, item.Action); err != nil {
			_ = stager.ClearGenerationRules(nextGen) // Rollback nextGen staging
			return curGen, fmt.Errorf("staging failed for Port %d/%s (Rule %d): %w", item.DstPort, item.Protocol, item.RuleID, err)
		}
	}

	// 4. ATOMIC SWAP: Switch active generation in kernel BPF array map
	if err := stager.SetActiveGeneration(nextGen); err != nil {
		_ = stager.ClearGenerationRules(nextGen)
		return curGen, fmt.Errorf("failed to switch active generation to %d: %w", nextGen, err)
	}

	// 5. Post-swap cleanup: purge old generation rules
	_ = stager.ClearGenerationRules(curGen)

	return nextGen, nil
}

