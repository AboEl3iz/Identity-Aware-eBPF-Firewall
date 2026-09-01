package main

import (
	"flag"
	"fmt"
	"os"

	"policy_engine/pkg/control"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	socketPath := "/var/run/firewall-agent.sock"

	cmd := os.Args[1]
	switch cmd {
	case "policy":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		subCmd := os.Args[2]
		switch subCmd {
		case "apply":
			fs := flag.NewFlagSet("policy apply", flag.ExitOnError)
			fileFlag := fs.String("f", "", "Path to YAML policy file")
			sockFlag := fs.String("socket", socketPath, "Path to agent Unix socket")
			_ = fs.Parse(os.Args[3:])

			if *fileFlag == "" {
				fmt.Println("[!] Error: --f <file.yaml> is required for 'policy apply'")
				os.Exit(1)
			}

			client := control.NewControlClient(*sockFlag)
			resp, err := client.ApplyPolicyFile(*fileFlag)
			if err != nil {
				fmt.Printf("[!] Failed to apply policy: %v\n", err)
				os.Exit(1)
			}

			if !resp.Success {
				fmt.Printf("[!] Policy apply failed: %s\n", resp.Error)
				if resp.CallerRole != "" {
					fmt.Printf("    Caller Identity: UID=%d Role=%s\n", resp.CallerUID, resp.CallerRole)
				}
				os.Exit(1)
			}

			fmt.Printf("[+] Policy applied successfully!\n")
			fmt.Printf("    Caller Identity:   UID=%d (Role: %s)\n", resp.CallerUID, resp.CallerRole)
			fmt.Printf("    Active Generation: %d\n", resp.ActiveGeneration)
			fmt.Printf("    Rules Staged:      %d\n", resp.RulesCount)

		case "status":
			fs := flag.NewFlagSet("policy status", flag.ExitOnError)
			sockFlag := fs.String("socket", socketPath, "Path to agent Unix socket")
			_ = fs.Parse(os.Args[3:])

			client := control.NewControlClient(*sockFlag)
			resp, err := client.GetStatus()
			if err != nil {
				fmt.Printf("[!] Failed to get status: %v\n", err)
				os.Exit(1)
			}

			if !resp.Success {
				fmt.Printf("[!] Error getting status: %s\n", resp.Error)
				os.Exit(1)
			}

			fmt.Println("=== Firewall Agent Status ===")
			if resp.CallerRole != "" {
				fmt.Printf("Authenticated As:  UID=%d (Role: %s)\n", resp.CallerUID, resp.CallerRole)
			}
			fmt.Printf("Active Generation: %d\n", resp.ActiveGeneration)
			if resp.Stats != nil {
				fmt.Printf("RX Packets:        %d\n", resp.Stats.RxPackets)
				fmt.Printf("RX Bytes:          %d\n", resp.Stats.RxBytes)
				fmt.Printf("PASS Packets:      %d\n", resp.Stats.PassPackets)
				fmt.Printf("DROP Packets:      %d\n", resp.Stats.DropPackets)
			}
			if resp.SockopsEnabled {
				fmt.Println("\n--- Sockops Direct Redirect ---")
				if resp.SockopsStats != nil {
					fmt.Printf("  Sockops Events:    %d\n", resp.SockopsStats.RxPackets)
					fmt.Printf("  Redirected:        %d\n", resp.SockopsStats.PassPackets)
					fmt.Printf("  Redirect Bytes:    %d\n", resp.SockopsStats.RxBytes)
					fmt.Printf("  Redirect Failures: %d\n", resp.SockopsStats.DropPackets)
				}
			}

		default:
			printUsage()
			os.Exit(1)
		}

	case "map":
		if len(os.Args) < 3 || os.Args[2] != "dump" {
			printUsage()
			os.Exit(1)
		}

		fs := flag.NewFlagSet("map dump", flag.ExitOnError)
		sockFlag := fs.String("socket", socketPath, "Path to agent Unix socket")
		_ = fs.Parse(os.Args[3:])

		client := control.NewControlClient(*sockFlag)
		resp, err := client.DumpMaps()
		if err != nil {
			fmt.Printf("[!] Failed to dump BPF maps: %v\n", err)
			os.Exit(1)
		}

		if !resp.Success {
			fmt.Printf("[!] Error dumping maps: %s\n", resp.Error)
			os.Exit(1)
		}

		fmt.Println("=== Active BPF Map State ===")
		if resp.CallerRole != "" {
			fmt.Printf("Authenticated As:  UID=%d (Role: %s)\n", resp.CallerUID, resp.CallerRole)
		}
		fmt.Printf("Active Generation: %d\n", resp.ActiveGeneration)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: firewall-ctl <command> [options]")
	fmt.Println("Commands:")
	fmt.Println("  policy apply -f <file.yaml> [--socket <path>]   Apply policy file atomically")
	fmt.Println("  policy status [--socket <path>]                 Show firewall agent status")
	fmt.Println("  map dump [--socket <path>]                      Dump active BPF map rules")
}

