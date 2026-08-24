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
	"policy_engine/pkg/observability"
)

func main() {
	iface := flag.String("iface", "veth-s", "Network interface to attach XDP firewall")
	configPath := flag.String("config", "configs/policy.example.yaml", "Path to YAML policy file")
	blockCIDR := flag.String("block-cidr", "", "Optional CIDR block rule (e.g. 10.0.0.1/32)")
	flag.Parse()

	log.Printf("[+] Starting eBPF Firewall Agent on interface '%s'...", *iface)

	// Initialize BPF Loader & attach XDP hook
	loader, err := bpf.NewFirewallLoader(*iface)
	if err != nil {
		log.Fatalf("[!] Failed to initialize BPF loader: %v", err)
	}
	defer loader.Close()

	log.Printf("[+] XDP program successfully attached to interface '%s'.", *iface)

	// Load policies into BPF maps
	if *blockCIDR != "" {
		log.Printf("[+] Adding CIDR block rule: %s (Rule ID: 101)", *blockCIDR)
		if err := loader.AddBlockCIDR(*blockCIDR, 101); err != nil {
			log.Fatalf("[!] Failed to add block CIDR: %v", err)
		}
	} else if *configPath != "" {
		comp := compiler.NewCompiler()
		pol, err := comp.ParseFile(*configPath)
		if err != nil {
			log.Printf("[!] Warning: Could not parse config %s: %v. Continuing without initial rules.", *configPath, err)
		} else {
			log.Printf("[+] Policy '%s' loaded. Processing rules...", pol.Metadata.Name)
			for _, rule := range pol.Spec.Rules {
				if rule.Action == "deny" {
					for _, cidr := range rule.SrcCIDRs {
						log.Printf("[+] Adding CIDR block rule: %s (Rule ID: %d)", cidr, rule.ID)
						if err := loader.AddBlockCIDR(cidr, rule.ID); err != nil {
							log.Printf("[!] Error adding CIDR %s: %v", cidr, err)
						}
					}
				}
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start BPF Ring Buffer audit event streaming
	go func() {
		log.Println("[+] Ring buffer audit event stream active.")
		err := loader.ReadRingbuf(ctx, func(evt observability.AuditEvent) {
			log.Printf("[AUDIT EVENT] %s", evt.String())
		})
		if err != nil && ctx.Err() == nil {
			log.Printf("[!] Ringbuf consumer error: %v", err)
		}
	}()

	// Periodic stats reporter goroutine
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
			}
		}
	}()

	log.Println("[+] Firewall agent operational. Press Ctrl+C to terminate.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("[-] Shutting down firewall agent & detaching XDP program...")
	cancel()

	// Print final stats
	finalStats, err := loader.GetStats()
	if err == nil {
		log.Printf("[FINAL STATS] RX Packets: %d | RX Bytes: %d | PASS: %d | DROP: %d",
			finalStats.RxPackets, finalStats.RxBytes, finalStats.PassPackets, finalStats.DropPackets)
	}
}
