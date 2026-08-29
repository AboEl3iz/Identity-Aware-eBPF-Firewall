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
	"policy_engine/pkg/observability"
	"policy_engine/pkg/security"
)

type Request struct {
	Command    string `json:"command"`              // "apply_policy", "get_status", "dump_maps"
	PolicyYAML string `json:"policy_yaml,omitempty"` // For apply_policy
}

type Response struct {
	Success          bool                       `json:"success"`
	Error            string                     `json:"error,omitempty"`
	ActiveGeneration uint32                     `json:"active_generation"`
	RulesCount       int                        `json:"rules_count"`
	Interface        string                     `json:"interface,omitempty"`
	CallerUID        uint32                     `json:"caller_uid,omitempty"`
	CallerPID        int32                      `json:"caller_pid,omitempty"`
	CallerRole       security.Role              `json:"caller_role,omitempty"`
	Stats            *StatsSummary              `json:"stats,omitempty"`
	Conntrack        []ConntrackFlowSummary     `json:"conntrack,omitempty"`
	AuditEvents      []observability.AuditEvent `json:"audit_events,omitempty"`
	Dump             *MapDumpSummary            `json:"dump,omitempty"`
}

type ConntrackFlowSummary struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`
	State    string `json:"state"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
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
	auditStore *observability.AuditStore
	compiler   *compiler.Compiler
	swapper    *compiler.MapSwapper
	rbac       *security.RBACEnforcer
	listener   net.Listener
}

func NewControlServer(socketPath string, loader *bpf.FirewallLoader, auditStore *observability.AuditStore) *ControlServer {
	return &ControlServer{
		socketPath: socketPath,
		loader:     loader,
		auditStore: auditStore,
		compiler:   compiler.NewCompiler(),
		swapper:    compiler.NewMapSwapper(),
		rbac:       security.NewRBACEnforcer(),
	}
}

func (s *ControlServer) RBAC() *security.RBACEnforcer {
	return s.rbac
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

	peerIdent, err := security.GetPeerCredentials(conn)
	if err != nil {
		log.Printf("[SECURITY] Warning: Could not extract socket peer credentials: %v", err)
		peerIdent = &security.PeerIdentity{UID: 65534, GID: 65534, PID: 0, Role: security.RoleViewer}
	} else {
		peerIdent.Role = s.rbac.ResolveRole(peerIdent)
	}

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req Request
	if err := decoder.Decode(&req); err != nil {
		if err != io.EOF {
			_ = encoder.Encode(Response{
				Success:    false,
				Error:      fmt.Sprintf("invalid JSON payload: %v", err),
				CallerUID:  peerIdent.UID,
				CallerPID:  peerIdent.PID,
				CallerRole: peerIdent.Role,
			})
		}
		return
	}

	// RBAC Authorization Check
	if permErr := s.rbac.EvaluatePermission(peerIdent.Role, req.Command); permErr != nil {
		log.Printf("[SECURITY] RBAC Deny: Caller %s attempted command '%s' -> %v", peerIdent.String(), req.Command, permErr)
		_ = encoder.Encode(Response{
			Success:    false,
			Error:      permErr.Error(),
			CallerUID:  peerIdent.UID,
			CallerPID:  peerIdent.PID,
			CallerRole: peerIdent.Role,
		})
		return
	}

	log.Printf("[SECURITY] RBAC Allow: Caller %s executing command '%s'", peerIdent.String(), req.Command)
	resp := s.processRequest(req)
	resp.CallerUID = peerIdent.UID
	resp.CallerPID = peerIdent.PID
	resp.CallerRole = peerIdent.Role
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

		var newGen uint32
		if s.loader != nil {
			g, err := s.swapper.ApplyPolicyAtomic(s.loader, cp)
			if err != nil {
				return Response{Success: false, Error: fmt.Sprintf("atomic reload error: %v", err)}
			}
			newGen = g
		} else {
			newGen = 1
		}

		rulesCount := len(cp.CIDRBlocks) + len(cp.CgroupBlocks) + len(cp.PortRules)
		log.Printf("[+] Policy '%s' applied. New Active Generation: %d (Rules: %d)", pol.Metadata.Name, newGen, rulesCount)

		return Response{
			Success:          true,
			ActiveGeneration: newGen,
			RulesCount:       rulesCount,
		}

	case "get_status":
		var gen uint32
		var stats *StatsSummary
		var ctSummaries []ConntrackFlowSummary

		if s.loader != nil {
			g, err := s.loader.GetActiveGeneration()
			if err != nil {
				return Response{Success: false, Error: fmt.Sprintf("failed getting generation: %v", err)}
			}
			gen = g

			if st, err := s.loader.GetStats(); err == nil {
				stats = &StatsSummary{
					RxPackets:   st.RxPackets,
					RxBytes:     st.RxBytes,
					PassPackets: st.PassPackets,
					DropPackets: st.DropPackets,
				}
			}

			if flows, err := s.loader.GetConntrackFlows(); err == nil {
				for _, f := range flows {
					stateStr := "UNKNOWN"
					switch f.State {
					case 1:
						stateStr = "SYN_SENT"
					case 2:
						stateStr = "ESTABLISHED"
					case 3:
						stateStr = "CLOSED"
					}

					ctSummaries = append(ctSummaries, ConntrackFlowSummary{
						SrcIP:    f.SrcIP.String(),
						DstIP:    f.DstIP.String(),
						SrcPort:  f.SrcPort,
						DstPort:  f.DstPort,
						Protocol: f.Protocol,
						State:    stateStr,
						Packets:  f.Packets,
						Bytes:    f.Bytes,
					})
				}
			}
		}

		var auditEvts []observability.AuditEvent
		if s.auditStore != nil {
			auditEvts = s.auditStore.Events()
		}

		return Response{
			Success:          true,
			ActiveGeneration: gen,
			Stats:            stats,
			Conntrack:        ctSummaries,
			AuditEvents:      auditEvts,
		}

	case "dump_maps":
		var gen uint32
		var ctSummaries []ConntrackFlowSummary

		if s.loader != nil {
			gen, _ = s.loader.GetActiveGeneration()
			if flows, err := s.loader.GetConntrackFlows(); err == nil {
				for _, f := range flows {
					stateStr := "UNKNOWN"
					switch f.State {
					case 1:
						stateStr = "SYN_SENT"
					case 2:
						stateStr = "ESTABLISHED"
					case 3:
						stateStr = "CLOSED"
					}

					ctSummaries = append(ctSummaries, ConntrackFlowSummary{
						SrcIP:    f.SrcIP.String(),
						DstIP:    f.DstIP.String(),
						SrcPort:  f.SrcPort,
						DstPort:  f.DstPort,
						Protocol: f.Protocol,
						State:    stateStr,
						Packets:  f.Packets,
						Bytes:    f.Bytes,
					})
				}
			}
		}

		var auditEvts []observability.AuditEvent
		if s.auditStore != nil {
			auditEvts = s.auditStore.Events()
		}

		return Response{
			Success:          true,
			ActiveGeneration: gen,
			Conntrack:        ctSummaries,
			AuditEvents:      auditEvts,
			Dump: &MapDumpSummary{
				ActiveGeneration: gen,
			},
		}

	default:
		return Response{Success: false, Error: fmt.Sprintf("unknown command: %s", req.Command)}
	}
}


