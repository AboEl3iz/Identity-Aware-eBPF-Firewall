package compiler

// Policy represents the top-level YAML policy structure.
type Policy struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Metadata   Metadata   `yaml:"metadata"`
	Spec       PolicySpec `yaml:"spec"`
}

type Metadata struct {
	Name string `yaml:"name"`
}

type PolicySpec struct {
	DefaultAction string `yaml:"defaultAction"`
	Rules         []Rule `yaml:"rules"`
}

type Rule struct {
	ID         uint32   `yaml:"id"`
	Name       string   `yaml:"name"`
	Action     string   `yaml:"action"` // "allow" or "deny"
	SrcCIDRs   []string `yaml:"srcCIDRs,omitempty"`
	DstPorts   []uint16 `yaml:"dstPorts,omitempty"`
	Protocols  []string `yaml:"protocols,omitempty"`
	SrcCgroups []string `yaml:"srcCgroups,omitempty"`
}

// CompiledPolicy represents verified and expanded policy elements ready for BPF staging.
type CompiledPolicy struct {
	Name          string
	DefaultAction string
	CIDRBlocks    []CompiledCIDR
	CgroupBlocks  []CompiledCgroup
	PortRules     []CompiledPortRule
}

type CompiledCIDR struct {
	RuleID  uint32
	CIDRStr string
	Action  string
}

type CompiledCgroup struct {
	RuleID     uint32
	CgroupPath string
	Action     string
}

type CompiledPortRule struct {
	RuleID   uint32
	DstPort  uint16
	Protocol string // "tcp", "udp", "icmp"
	Action   string // "allow", "deny"
}

