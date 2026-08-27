package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"policy_engine/pkg/bpf"
	"policy_engine/pkg/compiler"
	"policy_engine/pkg/conntrack"
	"policy_engine/pkg/control"
	"policy_engine/pkg/observability"
)

func main() {
	iface := flag.String("iface", "veth-s", "Network interface to attach XDP & TC firewall")
	configPath := flag.String("config", "configs/policy.example.yaml", "Path to YAML policy file")
	socketPath := flag.String("socket", "/var/run/firewall-agent.sock", "Path to Unix domain socket for IPC control plane")
	blockCIDR := flag.String("block-cidr", "", "Optional CIDR block rule (e.g. 10.0.0.1/32)")
	blockCgroup := flag.String("block-cgroup", "", "Optional cgroup path block rule (e.g. /sys/fs/cgroup/test-app-blocked)")
	flag.Parse()

	log.Printf("[+] Starting eBPF Firewall Agent on interface '%s'...", *iface)

	// Initialize BPF Loader & attach XDP + TC hooks
	loader, err := bpf.NewFirewallLoader(*iface)
	if err != nil {
		log.Fatalf("[!] Failed to initialize BPF loader: %v", err)
	}
	defer loader.Close()

	log.Printf("[+] XDP & TC programs successfully attached to interface '%s'.", *iface)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	auditStore := observability.NewAuditStore(1000)

	// Start Unix Domain Socket Control Server
	ctrlServer := control.NewControlServer(*socketPath, loader, auditStore)
	go func() {
		if err := ctrlServer.Start(ctx); err != nil {
			log.Printf("[!] Control Server error: %v", err)
		}
	}()

	// Load CIDR block rule if specified
	if *blockCIDR != "" {
		log.Printf("[+] Adding CIDR block rule: %s (Rule ID: 101)", *blockCIDR)
		if err := loader.AddBlockCIDR(*blockCIDR, 101); err != nil {
			log.Fatalf("[!] Failed to add block CIDR: %v", err)
		}
	}

	// Load Cgroup block rule if specified
	if *blockCgroup != "" {
		log.Printf("[+] Adding Cgroup block rule: %s (Rule ID: 103)", *blockCgroup)
		if err := loader.AddCgroupPathBlock(*blockCgroup, 103); err != nil {
			log.Printf("[!] Warning: Could not resolve/add cgroup block rule for '%s': %v", *blockCgroup, err)
		}
	}

	// Parse & compile policy config file if specified
	if *configPath != "" && *blockCIDR == "" && *blockCgroup == "" {
		comp := compiler.NewCompiler()
		pol, err := comp.ParseFile(*configPath)
		if err != nil {
			log.Printf("[!] Warning: Could not parse config %s: %v. Continuing without initial rules.", *configPath, err)
		} else {
			cp, err := comp.Compile(pol)
			if err != nil {
				log.Printf("[!] Warning: Could not compile policy AST: %v", err)
			} else {
				swapper := compiler.NewMapSwapper()
				gen, err := swapper.ApplyPolicyAtomic(loader, cp)
				if err != nil {
					log.Printf("[!] Warning: Could not apply initial policy atomically: %v", err)
				} else {
					log.Printf("[+] Policy '%s' loaded atomically (Generation %d).", pol.Metadata.Name, gen)
				}
			}
		}
	}

	// Start BPF Ring Buffer audit event streaming
	go func() {
		log.Println("[+] Ring buffer audit event stream active.")
		err := loader.ReadRingbuf(ctx, func(evt observability.AuditEvent) {
			log.Printf("[AUDIT EVENT] %s", evt.String())
			auditStore.Add(evt)
		})
		if err != nil && ctx.Err() == nil {
			log.Printf("[!] Ringbuf consumer error: %v", err)
		}
	}()

	conntrackTable := conntrack.NewTable()

	// Periodic stats & conntrack reporter goroutine
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats, err := loader.GetStats()
				if err == nil && stats.RxPackets > 0 {
					log.Printf("[STATS] RX Packets: %d | RX Bytes: %d | PASS: %d | DROP: %d",
						stats.RxPackets, stats.RxBytes, stats.PassPackets, stats.DropPackets)
				}

				// Report active conntrack flows
				flows, err := conntrackTable.SyncFromKernel(loader)
				if err == nil && len(flows) > 0 {
					for _, flow := range flows {
						log.Printf("[CONNTRACK] Flow %s:%d -> %s:%d (Proto %d) State: %s Packets: %d Bytes: %d",
							flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol, flow.State, flow.Packets, flow.Bytes)
					}
				}
			}
		}
	}()

	log.Println("[+] Firewall agent operational (XDP + TC Conntrack + Control Server active). Press Ctrl+C to terminate.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("[-] Shutting down firewall agent & detaching XDP/TC programs...")
	cancel()

	// Print final stats
	finalStats, err := loader.GetStats()
	if err == nil {
		log.Printf("[FINAL STATS] RX Packets: %d | RX Bytes: %d | PASS: %d | DROP: %d",
			finalStats.RxPackets, finalStats.RxBytes, finalStats.PassPackets, finalStats.DropPackets)
	}
}

