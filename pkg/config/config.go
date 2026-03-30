package config

import (
	"encoding/json"
	"os"
	"time"
)

// Config represents the main configuration for the firewall
type Config struct {
	// General settings
	LogLevel       string `json:"log_level"`
	LogFile        string `json:"log_file"`
	PIDFile        string `json:"pid_file"`
	DataDir        string `json:"data_dir"`
	
	// Rate limiting settings
	RateLimit      RateLimitConfig `json:"rate_limit"`
	
	// WAF settings
	WAF            WAFConfig `json:"waf"`
	
	// Shield settings
	Shield         ShieldConfig `json:"shield"`
	
	// Antivirus settings
	Antivirus      AntivirusConfig `json:"antivirus"`
	
	// API settings
	API            APIConfig `json:"api"`
	
	// Network settings
	Network        NetworkConfig `json:"network"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled          bool          `json:"enabled"`
	BurstWindow      time.Duration `json:"burst_window"`
	BurstLimit       int           `json:"burst_limit"`
	SustainedWindow  time.Duration `json:"sustained_window"`
	SustainedLimit   int           `json:"sustained_limit"`
	Whitelist        []string      `json:"whitelist"`
	Blacklist        []string      `json:"blacklist"`
	BlockDuration    time.Duration `json:"block_duration"`
}

// WAFConfig holds Web Application Firewall configuration
type WAFConfig struct {
	Enabled            bool     `json:"enabled"`
	DetectSQLInjection bool     `json:"detect_sql_injection"`
	DetectXSS          bool     `json:"detect_xss"`
	DetectPathTraversal bool    `json:"detect_path_traversal"`
	DetectRCE          bool     `json:"detect_rce"`
	DetectFileInclusion bool    `json:"detect_file_inclusion"`
	BlockBadBots       bool     `json:"block_bad_bots"`
	CustomRules        []Rule   `json:"custom_rules"`
}

// Rule represents a custom WAF rule
type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern"`
	Action      string   `json:"action"` // block, log, alert
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
}

// ShieldConfig holds kernel-level protection configuration
type ShieldConfig struct {
	Enabled              bool `json:"enabled"`
	DetectPortScans      bool `json:"detect_port_scans"`
	DetectSYNFlood       bool `json:"detect_syn_flood"`
	DetectInvalidPackets bool `json:"detect_invalid_packets"`
	DetectConnectionFlood bool `json:"detect_connection_flood"`
}

// AntivirusConfig holds antivirus scanning configuration
type AntivirusConfig struct {
	Enabled           bool          `json:"enabled"`
	ScanOnAccess      bool          `json:"scan_on_access"`
	ScanSchedule      string        `json:"scan_schedule"` // cron format
	QuarantineDir     string        `json:"quarantine_dir"`
	MaxFileSize       int64         `json:"max_file_size"`
	FileExtensions    []string      `json:"file_extensions"`
	ExcludePaths      []string      `json:"exclude_paths"`
}

// APIConfig holds threat intelligence API configuration
type APIConfig struct {
	Enabled           bool          `json:"enabled"`
	BaseURL           string        `json:"base_url"`
	APIKey            string        `json:"api_key"`
	CacheEnabled      bool          `json:"cache_enabled"`
	CacheDuration     time.Duration `json:"cache_duration"`
	CircuitBreakerThreshold int      `json:"circuit_breaker_threshold"`
	CircuitBreakerTimeout time.Duration `json:"circuit_breaker_timeout"`
	Timeout           time.Duration `json:"timeout"`
	RetryCount        int           `json:"retry_count"`
	RetryDelay        time.Duration `json:"retry_delay"`
}

// NetworkConfig holds network-level configuration
type NetworkConfig struct {
	EnableIPv6       bool     `json:"enable_ipv6"`
	UseIPSet         bool     `json:"use_ipset"`
	IPSetName        string   `json:"ipset_name"`
	TrustedInterfaces []string `json:"trusted_interfaces"`
	ProtectedPorts   []int    `json:"protected_ports"`
	GeoIPBlocking    bool     `json:"geoip_blocking"`
	BlockedCountries []string `json:"blocked_countries"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		LogLevel: "info",
		LogFile:  "/var/log/luvd-firewall/luvd.log",
		PIDFile:  "/var/run/luvd-firewall.pid",
		DataDir:  "/var/lib/luvd-firewall",
		
		RateLimit: RateLimitConfig{
			Enabled:         true,
			BurstWindow:     3 * time.Second,
			BurstLimit:      15,
			SustainedWindow: 30 * time.Second,
			SustainedLimit:  150,
			Whitelist:       []string{},
			Blacklist:       []string{},
			BlockDuration:   3600 * time.Second, // 1 hour
		},
		
		WAF: WAFConfig{
			Enabled:             true,
			DetectSQLInjection:  true,
			DetectXSS:           true,
			DetectPathTraversal: true,
			DetectRCE:           true,
			DetectFileInclusion: true,
			BlockBadBots:        true,
			CustomRules:         []Rule{},
		},
		
		Shield: ShieldConfig{
			Enabled:              true,
			DetectPortScans:      true,
			DetectSYNFlood:       true,
			DetectInvalidPackets: true,
			DetectConnectionFlood: true,
		},
		
		Antivirus: AntivirusConfig{
			Enabled:        true,
			ScanOnAccess:   false,
			ScanSchedule:   "0 2 * * *", // Daily at 2 AM
			QuarantineDir:  "/var/quarantine/luvd",
			MaxFileSize:    100 * 1024 * 1024, // 100MB
			FileExtensions: []string{".exe", ".dll", ".so", ".php", ".js", ".py", ".sh"},
			ExcludePaths:   []string{"/proc", "/sys", "/dev"},
		},
		
		API: APIConfig{
			Enabled:               true,
			BaseURL:               "https://api.luveedu.com/v1",
			APIKey:                "",
			CacheEnabled:          true,
			CacheDuration:         300 * time.Second, // 5 minutes
			CircuitBreakerThreshold: 5,
			CircuitBreakerTimeout: 60 * time.Second,
			Timeout:               10 * time.Second,
			RetryCount:            3,
			RetryDelay:            1 * time.Second,
		},
		
		Network: NetworkConfig{
			EnableIPv6:       true,
			UseIPSet:         true,
			IPSetName:        "luvd-blocklist",
			TrustedInterfaces: []string{"lo"},
			ProtectedPorts:   []int{80, 443, 8080, 8443},
			GeoIPBlocking:    false,
			BlockedCountries: []string{},
		},
	}
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config if file doesn't exist
			return DefaultConfig(), nil
		}
		return nil, err
	}
	defer file.Close()
	
	config := DefaultConfig()
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}
	
	return config, nil
}

// SaveConfig saves configuration to a JSON file
func (c *Config) SaveConfig(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}
