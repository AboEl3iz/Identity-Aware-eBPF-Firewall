package compiler

// Policy represents the top-level YAML policy structure.
type Policy struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
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
	ID          uint32   `yaml:"id"`
	Name        string   `yaml:"name"`
	Action      string   `yaml:"action"` // "allow" or "deny"
	SrcCIDRs    []string `yaml:"srcCIDRs,omitempty"`
	DstPorts    []uint16 `yaml:"dstPorts,omitempty"`
	Protocols   []string `yaml:"protocols,omitempty"`
	SrcCgroups  []string `yaml:"srcCgroups,omitempty"`
}
