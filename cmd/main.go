package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Luveedu/Luveedu-Firewall/internal/config"
	"github.com/Luveedu/Luveedu-Firewall/internal/engine"
	"github.com/Luveedu/Luveedu-Firewall/internal/scanner"
	"github.com/Luveedu/Luveedu-Firewall/internal/waf"
	"github.com/spf13/cobra"
)

var (
	cfgFile     string
	logLevel    string
	version     = "1.0.0"
	showVersion bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "luvd-firewall",
		Short: "Luveedu Enterprise Firewall - Advanced Security Solution",
		Long: `Luveedu Firewall is an enterprise-grade security solution providing:
- Real-time DDoS/DoS protection
- Web Application Firewall (WAF)
- Malware scanning with ClamAV
- Rootkit detection
- IP reputation management
- Automated threat response`,
		RunE: runFirewall,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/opt/luveedu-firewall/config.json", "Config file path")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warn, error)")

	// Version command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Luveedu Firewall v%s\n", version)
		},
	})

	// Block command
	blockCmd := &cobra.Command{
		Use:   "block <ip>",
		Short: "Block an IP address",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return engine.BlockIP(ip, cfg)
		},
	}
	rootCmd.AddCommand(blockCmd)

	// Unblock command
	unblockCmd := &cobra.Command{
		Use:   "unblock <ip>",
		Short: "Unblock an IP address",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return engine.UnblockIP(ip, cfg)
		},
	}
	rootCmd.AddCommand(unblockCmd)

	// List command
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List blocked IPs",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return engine.ListBlocked(cfg)
		},
	}
	rootCmd.AddCommand(listCmd)

	// Stats command
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show firewall statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return engine.ShowStats(cfg)
		},
	}
	rootCmd.AddCommand(statsCmd)

	// Scan command
	scanCmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a path for malware",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return scanner.ScanPath(path, cfg)
		},
	}
	rootCmd.AddCommand(scanCmd)

	// WAF test command
	testWAFCmd := &cobra.Command{
		Use:   "test-waf",
		Short: "Test WAF rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return waf.RunTests(cfg)
		},
	}
	rootCmd.AddCommand(testWAFCmd)

	// Monitor command (for shield service)
	monitorCmd := &cobra.Command{
		Use:   "monitor",
		Short: "Start log monitoring daemon",
		RunE:  runMonitor,
	}
	rootCmd.AddCommand(monitorCmd)

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		engine.Cleanup()
		os.Exit(0)
	}()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runFirewall(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg.LogLevel = logLevel

	fmt.Printf("Starting Luveedu Firewall v%s...\n", version)
	fmt.Printf("Config: %s\n", cfgFile)
	fmt.Printf("Log Level: %s\n", logLevel)

	// Initialize components
	if err := engine.Initialize(cfg); err != nil {
		return fmt.Errorf("failed to initialize engine: %w", err)
	}

	if err := waf.Initialize(cfg); err != nil {
		return fmt.Errorf("failed to initialize WAF: %w", err)
	}

	// Start main event loop
	return engine.StartEventLoop(cfg)
}

func runMonitor(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg.LogLevel = logLevel

	fmt.Printf("Starting Luveedu Shield Monitor v%s...\n", version)

	// Start log monitoring
	return engine.StartLogMonitor(cfg)
}
