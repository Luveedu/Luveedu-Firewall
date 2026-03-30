package config

import (
	"encoding/json"
	"os"
	"time"
)

// Config holds the firewall configuration
type Config struct {
	LogFile          string        `json:"log_file"`
	SyslogFile       string        `json:"syslog_file"`
	BlockDuration    time.Duration `json:"block_duration_minutes"`
	RateLimitBurst   int           `json:"rate_limit_burst"`      // Requests per 3 seconds
	RateLimitSustain int           `json:"rate_limit_sustain"`    // Requests per 30 seconds
	WAFEnabled       bool          `json:"waf_enabled"`
	ScanEnabled      bool          `json:"scan_enabled"`
	APIEndpoint      string        `json:"api_endpoint"`
	APITimeout       time.Duration `json:"api_timeout_seconds"`
	IPSetname        string        `json:"ipset_name"`
	QuarantineDir    string        `json:"quarantine_dir"`
	Whitelist        []string      `json:"whitelist"`
	ListenPort       int           `json:"listen_port"`
	MaxWorkers       int           `json:"max_workers"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		LogFile:          "/var/log/openlitespeed/access.log",
		SyslogFile:       "/var/log/syslog",
		BlockDuration:    60 * time.Minute,
		RateLimitBurst:   15,
		RateLimitSustain: 150,
		WAFEnabled:       true,
		ScanEnabled:      true,
		APIEndpoint:      "https://api.luveedu.com/v1/threat",
		APITimeout:       5 * time.Second,
		IPSetname:        "luveedu_blocklist",
		QuarantineDir:    "/var/luveedu/quarantine",
		Whitelist:        []string{"127.0.0.1", "::1"},
		ListenPort:       8080,
		MaxWorkers:       4,
	}
}

// LoadConfig loads configuration from a JSON file or creates default
func LoadConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := DefaultConfig()
		if err := SaveConfig(path, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveConfig saves configuration to a JSON file
func SaveConfig(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
