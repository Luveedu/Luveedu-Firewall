package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds the firewall configuration
type Config struct {
	LogLevel       string        `json:"log_level"`
	Port           int           `json:"port"`
	BlockDuration  time.Duration `json:"block_duration"`
	MaxConnections int           `json:"max_connections"`
	RateLimit      RateLimit     `json:"rate_limit"`
	WAF            WAFConfig     `json:"waf"`
	Scanner        ScannerConfig `json:"scanner"`
	Whitelist      []string      `json:"whitelist"`
	Blacklist      []string      `json:"blacklist"`
	API            APIConfig     `json:"api"`
	LogPath        string        `json:"log_path"`
	DataPath       string        `json:"data_path"`
}

// RateLimit configuration
type RateLimit struct {
	Enabled       bool          `json:"enabled"`
	BurstWindow   time.Duration `json:"burst_window"`
	BurstLimit    int           `json:"burst_limit"`
	SustainedWindow time.Duration `json:"sustained_window"`
	SustainedLimit  int           `json:"sustained_limit"`
}

// WAFConfig for web application firewall
type WAFConfig struct {
	Enabled        bool     `json:"enabled"`
	SQLInjection   bool     `json:"sql_injection"`
	XSS            bool     `json:"xss"`
	PathTraversal  bool     `json:"path_traversal"`
	RCE            bool     `json:"rce"`
	FileInclusion  bool     `json:"file_inclusion"`
	BlockPatterns  []string `json:"block_patterns"`
	CustomRules    []Rule   `json:"custom_rules"`
}

// Rule represents a custom WAF rule
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"` // block, log, alert
	Description string `json:"description"`
}

// ScannerConfig for malware scanning
type ScannerConfig struct {
	Enabled       bool     `json:"enabled"`
	ClamAVSocket  string   `json:"clamav_socket"`
	RKHunter      bool     `json:"rkhunter"`
	ScanPaths     []string `json:"scan_paths"`
	QuarantineDir string   `json:"quarantine_dir"`
	AutoClean     bool     `json:"auto_clean"`
}

// APIConfig for threat intelligence
type APIConfig struct {
	Enabled      bool          `json:"enabled"`
	URL          string        `json:"url"`
	APIKey       string        `json:"api_key"`
	CacheTimeout time.Duration `json:"cache_timeout"`
	Timeout      time.Duration `json:"timeout"`
	RetryCount   int           `json:"retry_count"`
}

// DefaultConfig returns a default configuration
func Default() *Config {
	return &Config{
		LogLevel:       "info",
		Port:           8080,
		BlockDuration:  3600 * time.Second,
		MaxConnections: 1000,
		RateLimit: RateLimit{
			Enabled:        true,
			BurstWindow:    3 * time.Second,
			BurstLimit:     15,
			SustainedWindow: 30 * time.Second,
			SustainedLimit:  150,
		},
		WAF: WAFConfig{
			Enabled:       true,
			SQLInjection:  true,
			XSS:           true,
			PathTraversal: true,
			RCE:           true,
			FileInclusion: true,
		},
		Scanner: ScannerConfig{
			Enabled:       true,
			ClamAVSocket:  "/var/run/clamav/clamd.ctl",
			RKHunter:      true,
			ScanPaths:     []string{"/var/www", "/home"},
			QuarantineDir: "/opt/luveedu-firewall/quarantine",
			AutoClean:     false,
		},
		API: APIConfig{
			Enabled:      true,
			URL:          "https://api.luveedu.com/threat-intel",
			CacheTimeout: 300 * time.Second,
			Timeout:      10 * time.Second,
			RetryCount:   3,
		},
		LogPath:  "/var/log/luveedu",
		DataPath: "/opt/luveedu-firewall/data",
	}
}

// Load loads configuration from a JSON file
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config if file doesn't exist
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// Save saves configuration to a JSON file
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}

	if c.BlockDuration < 0 {
		return fmt.Errorf("block duration cannot be negative")
	}

	if c.MaxConnections < 1 {
		return fmt.Errorf("max connections must be at least 1")
	}

	if c.RateLimit.Enabled {
		if c.RateLimit.BurstLimit <= 0 {
			return fmt.Errorf("burst limit must be positive")
		}
		if c.RateLimit.SustainedLimit <= 0 {
			return fmt.Errorf("sustained limit must be positive")
		}
	}

	return nil
}
