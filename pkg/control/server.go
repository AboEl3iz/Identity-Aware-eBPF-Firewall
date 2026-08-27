package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"policy_engine/pkg/bpf"
	"policy_engine/pkg/compiler"
)

type Request struct {
	Command    string `json:"command"`              // "apply_policy", "get_status", "dump_maps"
	PolicyYAML string `json:"policy_yaml,omitempty"` // For apply_policy
}

type Response struct {
	Success          bool            `json:"success"`
	Error            string          `json:"error,omitempty"`
	ActiveGeneration uint32          `json:"active_generation"`
	RulesCount       int             `json:"rules_count"`
	Interface        string          `json:"interface,omitempty"`
	Stats            *StatsSummary   `json:"stats,omitempty"`
	Dump             *MapDumpSummary `json:"dump,omitempty"`
}

type StatsSummary struct {
	RxPackets   uint64 `json:"rx_packets"`
	RxBytes     uint64 `json:"rx_bytes"`
	PassPackets uint64 `json:"pass_packets"`
	DropPackets uint64 `json:"drop_packets"`
}

type MapDumpSummary struct {
	ActiveGeneration uint32           `json:"active_generation"`
	CIDRRules        []CIDRRuleDump   `json:"cidr_rules"`
	CgroupRules      []CgroupRuleDump `json:"cgroup_rules"`
	PortRules        []PortRuleDump   `json:"port_rules"`
}

type CIDRRuleDump struct {
	Generation uint32 `json:"generation"`
	RuleID     uint32 `json:"rule_id"`
	PrefixLen  uint32 `json:"prefix_len"`
	Addr       string `json:"addr"`
}

type CgroupRuleDump struct {
	Generation uint32 `json:"generation"`
	RuleID     uint32 `json:"rule_id"`
	CgroupID   uint64 `json:"cgroup_id"`
}

type PortRuleDump struct {
	Generation uint32 `json:"generation"`
	RuleID     uint32 `json:"rule_id"`
	Port       uint16 `json:"port"`
	Protocol   string `json:"protocol"`
	Action     string `json:"action"`
}

type ControlServer struct {
	socketPath string
	loader     *bpf.FirewallLoader
	compiler   *compiler.Compiler
	swapper    *compiler.MapSwapper
	listener   net.Listener
}

func NewControlServer(socketPath string, loader *bpf.FirewallLoader) *ControlServer {
	return &ControlServer{
		socketPath: socketPath,
		loader:     loader,
		compiler:   compiler.NewCompiler(),
		swapper:    compiler.NewMapSwapper(),
	}
}

func (s *ControlServer) Start(ctx context.Context) error {
	_ = os.Remove(s.socketPath)

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket %s: %w", s.socketPath, err)
	}
	s.listener = l
	_ = os.Chmod(s.socketPath, 0666)

	log.Printf("[+] Control Plane IPC server listening on unix socket: %s", s.socketPath)

	go func() {
		<-ctx.Done()
		l.Close()
		os.Remove(s.socketPath)
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *ControlServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req Request
	if err := decoder.Decode(&req); err != nil {
		if err != io.EOF {
			encoder.Encode(Response{Success: false, Error: fmt.Sprintf("invalid JSON payload: %v", err)})
		}
		return
	}

	resp := s.processRequest(req)
	_ = encoder.Encode(resp)
}

func (s *ControlServer) processRequest(req Request) Response {
	switch req.Command {
	case "apply_policy":
		pol, err := s.compiler.Parse([]byte(req.PolicyYAML))
		if err != nil {
			return Response{Success: false, Error: fmt.Sprintf("policy parse error: %v", err)}
		}

		cp, err := s.compiler.Compile(pol)
		if err != nil {
			return Response{Success: false, Error: fmt.Sprintf("policy compilation error: %v", err)}
		}

		newGen, err := s.swapper.ApplyPolicyAtomic(s.loader, cp)
		if err != nil {
			return Response{Success: false, Error: fmt.Sprintf("atomic reload error: %v", err)}
		}

		rulesCount := len(cp.CIDRBlocks) + len(cp.CgroupBlocks) + len(cp.PortRules)
		log.Printf("[+] Policy '%s' applied atomically. New Active Generation: %d (Rules: %d)", pol.Metadata.Name, newGen, rulesCount)

		return Response{
			Success:          true,
			ActiveGeneration: newGen,
			RulesCount:       rulesCount,
		}

	case "get_status":
		gen, err := s.loader.GetActiveGeneration()
		if err != nil {
			return Response{Success: false, Error: fmt.Sprintf("failed getting generation: %v", err)}
		}

		stats, _ := s.loader.GetStats()
		return Response{
			Success:          true,
			ActiveGeneration: gen,
			Stats: &StatsSummary{
				RxPackets:   stats.RxPackets,
				RxBytes:     stats.RxBytes,
				PassPackets: stats.PassPackets,
				DropPackets: stats.DropPackets,
			},
		}

	case "dump_maps":
		gen, _ := s.loader.GetActiveGeneration()
		return Response{
			Success:          true,
			ActiveGeneration: gen,
			Dump: &MapDumpSummary{
				ActiveGeneration: gen,
			},
		}

	default:
		return Response{Success: false, Error: fmt.Sprintf("unknown command: %s", req.Command)}
	}
}
