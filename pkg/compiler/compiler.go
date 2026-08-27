package compiler

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Compiler validates policy AST and generates key/value map entries.
type Compiler struct{}

func NewCompiler() *Compiler {
	return &Compiler{}
}

func (c *Compiler) ParseFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	return c.Parse(data)
}

func (c *Compiler) Parse(data []byte) (*Policy, error) {
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	if err := c.Validate(&policy); err != nil {
		return nil, fmt.Errorf("policy AST validation failed: %w", err)
	}

	return &policy, nil
}

// Validate checks AST rules: API version, Kind, unique rule IDs, valid IP/CIDR formats, ports, and protocols.
func (c *Compiler) Validate(p *Policy) error {
	if p.APIVersion != "v1" {
		return fmt.Errorf("unsupported apiVersion '%s', expected 'v1'", p.APIVersion)
	}
	if p.Kind != "FirewallPolicy" {
		return fmt.Errorf("unsupported kind '%s', expected 'FirewallPolicy'", p.Kind)
	}

	defAct := strings.ToLower(strings.TrimSpace(p.Spec.DefaultAction))
	if defAct != "" && defAct != "allow" && defAct != "deny" {
		return fmt.Errorf("invalid defaultAction '%s', expected 'allow' or 'deny'", p.Spec.DefaultAction)
	}

	seenIDs := make(map[uint32]string)
	for i, rule := range p.Spec.Rules {
		if rule.ID == 0 {
			return fmt.Errorf("rule #%d ('%s') has invalid ID 0", i, rule.Name)
		}
		if existingName, exists := seenIDs[rule.ID]; exists {
			return fmt.Errorf("duplicate rule ID %d found in rules '%s' and '%s'", rule.ID, existingName, rule.Name)
		}
		seenIDs[rule.ID] = rule.Name

		act := strings.ToLower(strings.TrimSpace(rule.Action))
		if act != "allow" && act != "deny" {
			return fmt.Errorf("rule ID %d ('%s') has invalid action '%s', expected 'allow' or 'deny'", rule.ID, rule.Name, rule.Action)
		}

		for _, cidr := range rule.SrcCIDRs {
			_, _, err := net.ParseCIDR(cidr)
			if err != nil {
				ip := net.ParseIP(cidr)
				if ip == nil {
					return fmt.Errorf("rule ID %d ('%s') has invalid CIDR or IP address '%s'", rule.ID, rule.Name, cidr)
				}
			}
		}

		for _, port := range rule.DstPorts {
			if port == 0 {
				return fmt.Errorf("rule ID %d ('%s') has invalid port number 0", rule.ID, rule.Name)
			}
		}

		for _, proto := range rule.Protocols {
			pLower := strings.ToLower(strings.TrimSpace(proto))
			if pLower != "tcp" && pLower != "udp" && pLower != "icmp" {
				return fmt.Errorf("rule ID %d ('%s') has unsupported protocol '%s', expected 'tcp', 'udp', or 'icmp'", rule.ID, rule.Name, proto)
			}
		}
	}

	return nil
}

// Compile generates a CompiledPolicy ready for atomic BPF map staging.
func (c *Compiler) Compile(p *Policy) (*CompiledPolicy, error) {
	if err := c.Validate(p); err != nil {
		return nil, err
	}

	defAct := strings.ToLower(strings.TrimSpace(p.Spec.DefaultAction))
	if defAct == "" {
		defAct = "allow"
	}

	cp := &CompiledPolicy{
		Name:          p.Metadata.Name,
		DefaultAction: defAct,
	}

	for _, rule := range p.Spec.Rules {
		action := strings.ToLower(strings.TrimSpace(rule.Action))

		for _, cidr := range rule.SrcCIDRs {
			cp.CIDRBlocks = append(cp.CIDRBlocks, CompiledCIDR{
				RuleID:  rule.ID,
				CIDRStr: cidr,
				Action:  action,
			})
		}

		for _, cg := range rule.SrcCgroups {
			cp.CgroupBlocks = append(cp.CgroupBlocks, CompiledCgroup{
				RuleID:     rule.ID,
				CgroupPath: cg,
				Action:     action,
			})
		}

		protocols := rule.Protocols
		if len(protocols) == 0 && len(rule.DstPorts) > 0 {
			protocols = []string{"tcp", "udp"}
		}

		for _, port := range rule.DstPorts {
			for _, proto := range protocols {
				cp.PortRules = append(cp.PortRules, CompiledPortRule{
					RuleID:   rule.ID,
					DstPort:  port,
					Protocol: strings.ToLower(strings.TrimSpace(proto)),
					Action:   action,
				})
			}
		}
	}

	return cp, nil
}

