package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"luveedu/config"
	"luveedu/engine"
	"luveedu/scanner"
	"luveedu/waf"
)

var (
	configPath   = flag.String("config", "/etc/luveedu/config.json", "Path to configuration file")
	action       = flag.String("action", "start", "Action: start, stop, status, block, unblock, list, scan, update")
	targetIP     = flag.String("ip", "", "Target IP address for block/unblock")
	scanPath     = flag.String("scan-path", "/", "Path to scan for malware")
	showHelp     = flag.Bool("help", false, "Show help message")
)

func main() {
	flag.Parse()

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	switch *action {
	case "start":
		runDaemon(cfg)
	case "stop":
		stopDaemon()
	case "status":
		showStatus(cfg)
	case "block":
		blockIP(cfg, *targetIP)
	case "unblock":
		unblockIP(cfg, *targetIP)
	case "list":
		listBlocked(cfg)
	case "scan":
		runScan(cfg, *scanPath)
	case "update":
		updateSignatures()
	case "test-waf":
		testWAF()
	default:
		fmt.Printf("Unknown action: %s\n", *action)
		printHelp()
		os.Exit(1)
	}
}

func runDaemon(cfg *config.Config) {
	fmt.Println("Starting Luveedu Firewall...")

	// Initialize ipset
	if err := engine.InitIPSet(cfg); err != nil {
		log.Printf("Warning: Failed to initialize ipset: %v", err)
	}

	// Ensure iptables rule
	if err := engine.EnsureIPTablesRule(cfg); err != nil {
		log.Printf("Warning: Failed to ensure iptables rule: %v", err)
	}

	// Create components
	rateLimiter := engine.NewRateLimiter(cfg)
	blocker := engine.NewBlocker(cfg)
	parser := engine.NewLogParser()
	wafEngine := waf.NewWAF()
	_ = scanner.NewScanner(cfg.QuarantineDir) // Available for future use

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start log monitoring in goroutine
	go func() {
		fmt.Println("Starting log monitoring...")
		if err := engine.MonitorLogs(ctx, cfg, rateLimiter, blocker, parser); err != nil {
			log.Printf("Log monitoring error: %v", err)
		}
	}()

	// Start periodic cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rateLimiter.CleanupOldRequests()
				fmt.Printf("[Cleanup] Active blocked IPs: %d\n", len(blocker.GetBlockedIPs()))
			}
		}
	}()

	// Start WAF HTTP server (optional - can be used as reverse proxy)
	if cfg.WAFEnabled {
		go func() {
			fmt.Printf("Starting WAF on port %d...\n", cfg.ListenPort)
			startWAFServer(cfg, wafEngine, blocker)
		}()
	}

	fmt.Println("Luveedu Firewall is running. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down gracefully...")
	cancel()
	time.Sleep(2 * time.Second)
	fmt.Println("Goodbye!")
}

func stopDaemon() {
	fmt.Println("Stopping Luveedu Firewall...")
	// In production, this would send SIGTERM to the running process
	cmd := exec.Command("pkill", "-f", "luveedu-firewall")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Failed to stop daemon: %v\n", err)
	} else {
		fmt.Println("Daemon stopped.")
	}
}

func showStatus(cfg *config.Config) {
	fmt.Println("=== Luveedu Firewall Status ===")
	
	// Check if process is running
	cmd := exec.Command("pgrep", "-f", "luveedu-firewall")
	if err := cmd.Run(); err == nil {
		fmt.Println("Status: RUNNING")
	} else {
		fmt.Println("Status: STOPPED")
	}

	// Show blocked IPs count
	blocker := engine.NewBlocker(cfg)
	blocked := blocker.GetBlockedIPs()
	fmt.Printf("Blocked IPs: %d\n", len(blocked))

	// Show ipset status
	cmd = exec.Command("ipset", "list", cfg.IPSetname)
	if output, err := cmd.Output(); err == nil {
		fmt.Println("\nipset status:")
		fmt.Println(string(output))
	}

	// Show configuration
	fmt.Printf("\nConfiguration:\n")
	fmt.Printf("  Log File: %s\n", cfg.LogFile)
	fmt.Printf("  Rate Limit Burst: %d req/3s\n", cfg.RateLimitBurst)
	fmt.Printf("  Rate Limit Sustain: %d req/30s\n", cfg.RateLimitSustain)
	fmt.Printf("  WAF Enabled: %v\n", cfg.WAFEnabled)
	fmt.Printf("  Scan Enabled: %v\n", cfg.ScanEnabled)
}

func blockIP(cfg *config.Config, ip string) {
	if ip == "" {
		fmt.Println("Error: IP address required. Use -ip flag.")
		os.Exit(1)
	}

	blocker := engine.NewBlocker(cfg)
	if err := blocker.BlockIP(ip, cfg.BlockDuration); err != nil {
		fmt.Printf("Failed to block IP: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully blocked IP: %s\n", ip)
}

func unblockIP(cfg *config.Config, ip string) {
	if ip == "" {
		fmt.Println("Error: IP address required. Use -ip flag.")
		os.Exit(1)
	}

	blocker := engine.NewBlocker(cfg)
	if err := blocker.UnblockIP(ip); err != nil {
		fmt.Printf("Failed to unblock IP: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully unblocked IP: %s\n", ip)
}

func listBlocked(cfg *config.Config) {
	blocker := engine.NewBlocker(cfg)
	ips := blocker.GetBlockedIPs()
	
	fmt.Printf("Currently Blocked IPs (%d):\n", len(ips))
	for _, ip := range ips {
		fmt.Printf("  - %s\n", ip)
	}
}

func runScan(cfg *config.Config, path string) {
	fmt.Printf("Scanning %s for malware...\n", path)

	sc := scanner.NewScanner(cfg.QuarantineDir)
	results, err := sc.ScanDirectory(path)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Println(scanner.GetScanSummary(results))
}

func updateSignatures() {
	fmt.Println("Updating virus signatures...")
	if err := scanner.UpdateSignatures(); err != nil {
		fmt.Printf("Warning: Failed to update signatures: %v\n", err)
	} else {
		fmt.Println("Signatures updated successfully.")
	}

	fmt.Println("Checking for rootkits...")
	warnings, err := scanner.CheckRootkit()
	if err != nil {
		fmt.Printf("Warning: Rootkit check failed: %v\n", err)
	} else if len(warnings) > 0 {
		fmt.Println("Rootkit warnings detected:")
		for _, w := range warnings {
			fmt.Printf("  %s\n", w)
		}
	} else {
		fmt.Println("No rootkit warnings detected.")
	}
}

func testWAF() {
	fmt.Println("Testing WAF patterns...")
	wafEngine := waf.NewWAF()

	testCases := []struct {
		name string
		path string
	}{
		{"SQL Injection", "/search?q=1%27%20OR%20%271%27=%271"},
		{"XSS", "/page?content=%3Cscript%3Ealert(%27xss%27)%3C/script%3E"},
		{"Path Traversal", "/files/../../../etc/passwd"},
		{"RCE", "/cmd?exec=cat%20/etc/passwd"},
		{"Clean", "/index.html"},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", tc.path, nil)
		threat, match := wafEngine.CheckRequest(req)
		if threat != waf.ThreatNone {
			fmt.Printf("✓ %s DETECTED: %s (match: %s)\n", tc.name, threat.String(), match)
		} else {
			fmt.Printf("✓ %s: Clean\n", tc.name)
		}
	}
}

func printHelp() {
	fmt.Println(`Luveedu Firewall - Enterprise-Grade Security Suite

Usage: luveedu-firewall [options]

Options:
  -config <path>      Path to configuration file (default: /etc/luveedu/config.json)
  -action <action>    Action to perform:
                      start       - Start the firewall daemon
                      stop        - Stop the firewall daemon
                      status      - Show firewall status
                      block       - Block an IP address (requires -ip)
                      unblock     - Unblock an IP address (requires -ip)
                      list        - List all blocked IPs
                      scan        - Scan for malware (requires -scan-path)
                      update      - Update virus signatures and check rootkits
                      test-waf    - Test WAF patterns
  -ip <address>       Target IP address for block/unblock actions
  -scan-path <path>   Directory path to scan for malware
  -help               Show this help message

Examples:
  sudo luveedu-firewall -action start
  sudo luveedu-firewall -action block -ip 192.168.1.100
  sudo luveedu-firewall -action scan -scan-path /var/www
  sudo luveedu-firewall -action update
`)
}
