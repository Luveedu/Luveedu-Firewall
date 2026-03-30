package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luveedu/luvd-firewall/pkg/config"
	"github.com/luveedu/luvd-firewall/pkg/engine"
	"github.com/luveedu/luvd-firewall/pkg/scanner"
	"github.com/luveedu/luvd-firewall/pkg/waf"
)

var (
	version     = "2.0.0"
	buildTime   = "unknown"
	gitCommit   = "unknown"
	configPath  string
	showVersion bool
	daemonMode  bool
)

func main() {
	flag.StringVar(&configPath, "config", "/etc/luvd-firewall/config.json", "Path to configuration file")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.BoolVar(&daemonMode, "daemon", false, "Run in daemon mode")
	
	// Subcommands
	flag.Parse()
	
	if showVersion {
		printVersion()
		os.Exit(0)
	}
	
	args := flag.Args()
	if len(args) > 0 {
		handleCommand(args[0], args[1:])
		return
	}
	
	// Start the firewall
	startFirewall()
}

func printVersion() {
	fmt.Printf("Luveedu Firewall v%s\n", version)
	fmt.Printf("Build Time: %s\n", buildTime)
	fmt.Printf("Git Commit: %s\n", gitCommit)
}

func handleCommand(cmd string, args []string) {
	switch cmd {
	case "start":
		startFirewall()
	case "stop":
		stopFirewall()
	case "status":
		showStatus()
	case "block":
		if len(args) < 1 {
			fmt.Println("Usage: luvd-firewall block <ip>")
			os.Exit(1)
		}
		blockIP(args[0])
	case "unblock":
		if len(args) < 1 {
			fmt.Println("Usage: luvd-firewall unblock <ip>")
			os.Exit(1)
		}
		unblockIP(args[0])
	case "list":
		listBlockedIPs()
	case "stats":
		showStats()
	case "scan":
		if len(args) < 1 {
			fmt.Println("Usage: luvd-firewall scan <path>")
			os.Exit(1)
		}
		scanPath(args[0])
	case "update":
		updateDefinitions()
	case "test-waf":
		testWAF()
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: luvd-firewall [options] [command]")
	fmt.Println("\nCommands:")
	fmt.Println("  start              Start the firewall")
	fmt.Println("  stop               Stop the firewall")
	fmt.Println("  status             Show firewall status")
	fmt.Println("  block <ip>         Block an IP address")
	fmt.Println("  unblock <ip>       Unblock an IP address")
	fmt.Println("  list               List blocked IPs")
	fmt.Println("  stats              Show firewall statistics")
	fmt.Println("  scan <path>        Scan a path for malware")
	fmt.Println("  update             Update virus definitions")
	fmt.Println("  test-waf           Test WAF rules")
	fmt.Println("\nOptions:")
	fmt.Println("  -config <path>     Path to configuration file")
	fmt.Println("  -version           Show version information")
	fmt.Println("  -daemon            Run in daemon mode")
}

func startFirewall() {
	fmt.Println("Starting Luveedu Firewall...")
	
	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	
	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Initialize components
	firewallEngine := engine.NewFirewallEngine(cfg)
	_ = waf.NewWAFEngine(&cfg.WAF) // WAF engine initialized for future use
	_ = scanner.NewMalwareScanner(&scanner.ScannerConfig{
		Enabled:        cfg.Antivirus.Enabled,
		QuarantineDir:  cfg.Antivirus.QuarantineDir,
		MaxFileSize:    cfg.Antivirus.MaxFileSize,
		FileExtensions: cfg.Antivirus.FileExtensions,
		ExcludePaths:   cfg.Antivirus.ExcludePaths,
	}) // Malware scanner ready for future use
	
	// Start firewall engine
	if err := firewallEngine.Start(ctx); err != nil {
		log.Fatalf("Failed to start firewall engine: %v", err)
	}
	
	fmt.Println("✓ Firewall engine started")
	fmt.Println("✓ WAF engine initialized")
	fmt.Println("✓ Malware scanner ready")
	
	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	if daemonMode {
		// Write PID file
		pidFile := cfg.PIDFile
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
			log.Printf("Warning: Failed to write PID file: %v", err)
		}
		fmt.Printf("✓ Running in daemon mode (PID: %d)\n", os.Getpid())
	}
	
	fmt.Println("\nLuveedu Firewall is now protecting your server!")
	fmt.Println("Press Ctrl+C to stop")
	
	// Wait for shutdown signal
	<-sigChan
	
	fmt.Println("\nShutting down...")
	cancel()
	firewallEngine.Stop()
	
	// Remove PID file
	if daemonMode {
		os.Remove(cfg.PIDFile)
	}
	
	fmt.Println("Firewall stopped")
}

func stopFirewall() {
	cfg, _ := config.LoadConfig(configPath)
	pidFile := cfg.PIDFile
	
	if data, err := os.ReadFile(pidFile); err == nil {
		var pid int
		fmt.Sscanf(string(data), "%d", &pid)
		
		process, err := os.FindProcess(pid)
		if err == nil {
			process.Signal(syscall.SIGTERM)
			fmt.Printf("Sent SIGTERM to process %d\n", pid)
		}
	} else {
		fmt.Println("Firewall is not running (no PID file found)")
	}
}

func showStatus() {
	cfg, _ := config.LoadConfig(configPath)
	pidFile := cfg.PIDFile
	
	if data, err := os.ReadFile(pidFile); err == nil {
		var pid int
		fmt.Sscanf(string(data), "%d", &pid)
		
		// Check if process is running
		process, err := os.FindProcess(pid)
		if err == nil {
			err = process.Signal(syscall.Signal(0))
			if err == nil {
				fmt.Println("✓ Luveedu Firewall is RUNNING")
				fmt.Printf("  PID: %d\n", pid)
				
				// Show basic stats
				showStats()
				return
			}
		}
	}
	
	fmt.Println("✗ Luveedu Firewall is NOT RUNNING")
}

func showStats() {
	cfg, _ := config.LoadConfig(configPath)
	firewallEngine := engine.NewFirewallEngine(cfg)
	stats := firewallEngine.GetStats()
	
	fmt.Println("=== Firewall Statistics ===")
	fmt.Printf("Total Requests:    %d\n", stats.TotalRequests)
	fmt.Printf("Blocked Requests:  %d\n", stats.BlockedRequests)
	fmt.Printf("Unique IPs:        %d\n", stats.UniqueIPs)
	fmt.Printf("Uptime:            %s\n", time.Since(stats.StartTime).Round(time.Second))
	fmt.Printf("Start Time:        %s\n", stats.StartTime.Format(time.RFC3339))
	
	blockedIPs, _ := firewallEngine.ListBlockedIPs()
	fmt.Printf("Currently Blocked: %d IPs\n", len(blockedIPs))
}

func blockIP(ip string) {
	cfg, _ := config.LoadConfig(configPath)
	firewallEngine := engine.NewFirewallEngine(cfg)
	
	duration := 1 * time.Hour // Default block duration
	if err := firewallEngine.BlockIP(ip, duration); err != nil {
		fmt.Printf("Failed to block IP: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("✓ Successfully blocked IP: %s for %v\n", ip, duration)
}

func unblockIP(ip string) {
	cfg, _ := config.LoadConfig(configPath)
	firewallEngine := engine.NewFirewallEngine(cfg)
	
	if err := firewallEngine.UnblockIP(ip); err != nil {
		fmt.Printf("Failed to unblock IP: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("✓ Successfully unblocked IP: %s\n", ip)
}

func listBlockedIPs() {
	cfg, _ := config.LoadConfig(configPath)
	firewallEngine := engine.NewFirewallEngine(cfg)
	
	ips, err := firewallEngine.ListBlockedIPs()
	if err != nil {
		fmt.Printf("Failed to list blocked IPs: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("=== Blocked IPs ===")
	if len(ips) == 0 {
		fmt.Println("No IPs currently blocked")
		return
	}
	
	for _, ip := range ips {
		fmt.Println(ip)
	}
	fmt.Printf("\nTotal: %d blocked IPs\n", len(ips))
}

func scanPath(path string) {
	cfg, _ := config.LoadConfig(configPath)
	malwareScanner := scanner.NewMalwareScanner(&scanner.ScannerConfig{
		Enabled:        cfg.Antivirus.Enabled,
		QuarantineDir:  cfg.Antivirus.QuarantineDir,
		MaxFileSize:    cfg.Antivirus.MaxFileSize,
		FileExtensions: cfg.Antivirus.FileExtensions,
		ExcludePaths:   cfg.Antivirus.ExcludePaths,
	})
	
	fmt.Printf("Scanning %s for malware...\n", path)
	
	results, err := malwareScanner.ScanDirectory(path)
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		os.Exit(1)
	}
	
	report := malwareScanner.GenerateReport(results)
	fmt.Println(report)
}

func updateDefinitions() {
	cfg, _ := config.LoadConfig(configPath)
	malwareScanner := scanner.NewMalwareScanner(&scanner.ScannerConfig{
		Enabled:        cfg.Antivirus.Enabled,
		QuarantineDir:  cfg.Antivirus.QuarantineDir,
	})
	
	fmt.Println("Updating virus definitions...")
	
	if err := malwareScanner.UpdateVirusDefinitions(); err != nil {
		fmt.Printf("Update failed: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("✓ Virus definitions updated successfully")
}

func testWAF() {
	cfg, _ := config.LoadConfig(configPath)
	wafEngine := waf.NewWAFEngine(&cfg.WAF)
	
	testCases := []struct {
		name string
		req  *waf.WAFRequest
	}{
		{
			name: "SQL Injection Test",
			req: &waf.WAFRequest{
				Method:    "GET",
				Path:      "/search",
				Query:     "q=' OR 1=1 --",
				UserAgent: "Mozilla/5.0",
			},
		},
		{
			name: "XSS Test",
			req: &waf.WAFRequest{
				Method:    "POST",
				Path:      "/comment",
				Body:      "<script>alert('xss')</script>",
				UserAgent: "Mozilla/5.0",
			},
		},
		{
			name: "Path Traversal Test",
			req: &waf.WAFRequest{
				Method:    "GET",
				Path:      "/files/../../../etc/passwd",
				UserAgent: "Mozilla/5.0",
			},
		},
		{
			name: "RCE Test",
			req: &waf.WAFRequest{
				Method:    "POST",
				Path:      "/api/exec",
				Body:      "cmd=ls -la | cat /etc/passwd",
				UserAgent: "Mozilla/5.0",
			},
		},
		{
			name: "Clean Request",
			req: &waf.WAFRequest{
				Method:    "GET",
				Path:      "/index.html",
				UserAgent: "Mozilla/5.0",
			},
		},
	}
	
	fmt.Println("=== WAF Rule Testing ===\n")
	
	for _, tc := range testCases {
		result := wafEngine.Analyze(tc.req)
		
		status := "✓ ALLOWED"
		if result.Blocked {
			status = "✗ BLOCKED"
		}
		
		fmt.Printf("[%s] %s\n", status, tc.name)
		if result.Blocked {
			fmt.Printf("  Rule: %s (%s)\n", result.RuleName, result.RuleID)
			fmt.Printf("  Category: %s\n", result.Category)
			fmt.Printf("  Description: %s\n", result.Description)
		}
		fmt.Println()
	}
}

// Helper function to pretty print JSON
func printJSON(v interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(v)
}
