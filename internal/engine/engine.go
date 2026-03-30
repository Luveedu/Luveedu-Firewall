package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Luveedu/Luveedu-Firewall/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	blockedIPs      = make(map[string]time.Time)
	blockedIPsMutex sync.RWMutex

	requestCounts   = make(map[string][]time.Time)
	requestCountsMutex sync.RWMutex

	statsMutex sync.RWMutex
	stats      = FirewallStats{
		StartTime:       time.Now(),
		TotalRequests:   0,
		BlockedRequests: 0,
		ActiveBlocks:    0,
	}

	// Prometheus metrics
	totalRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "luveedu_firewall_total_requests",
		Help: "Total number of requests processed",
	})
	blockedRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "luveedu_firewall_blocked_requests",
		Help: "Total number of blocked requests",
	})
	activeBlocks = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "luveedu_firewall_active_blocks",
		Help: "Current number of active IP blocks",
	})
)

// FirewallStats holds firewall statistics
type FirewallStats struct {
	StartTime       time.Time `json:"start_time"`
	TotalRequests   int64     `json:"total_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	ActiveBlocks    int       `json:"active_blocks"`
}

// Initialize sets up the firewall engine
func Initialize(cfg *config.Config) error {
	log.Printf("Initializing firewall engine...")

	// Create necessary directories
	dirs := []string{cfg.LogPath, cfg.DataPath, cfg.Scanner.QuarantineDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Initialize ipsets
	if err := initIPSets(); err != nil {
		return fmt.Errorf("failed to initialize ipsets: %w", err)
	}

	// Load existing blocks
	if err := loadBlockedIPs(cfg); err != nil {
		log.Printf("Warning: failed to load blocked IPs: %v", err)
	}

	log.Printf("Firewall engine initialized successfully")
	return nil
}

// initIPSets creates the required ipsets
func initIPSets() error {
	commands := []string{
		"ipset create -exist luvd_blacklist hash:ip timeout 0",
		"ipset create -exist luvd_whitelist hash:ip timeout 0",
		"ipset create -exist luvd_temp_block hash:ip timeout 3600",
	}

	for _, cmd := range commands {
		parts := strings.Fields(cmd)
		if err := exec.Command(parts[0], parts[1:]...).Run(); err != nil {
			// Ignore errors for existing sets
			if !strings.Contains(err.Error(), "already exists") {
				log.Printf("Warning: failed to execute %s: %v", cmd, err)
			}
		}
	}

	return nil
}

// loadBlockedIPs loads previously blocked IPs from disk
func loadBlockedIPs(cfg *config.Config) error {
	filePath := filepath.Join(cfg.DataPath, "blocked_ips.json")
	
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var savedBlocks map[string]time.Time
	if err := json.Unmarshal(data, &savedBlocks); err != nil {
		return err
	}

	now := time.Now()
	for ip, expiry := range savedBlocks {
		if expiry.IsZero() || expiry.After(now) {
			if err := addToIPSet(ip, cfg.BlockDuration); err == nil {
				blockedIPs[ip] = expiry
			}
		}
	}

	return nil
}

// saveBlockedIPs saves blocked IPs to disk
func saveBlockedIPs(cfg *config.Config) error {
	filePath := filepath.Join(cfg.DataPath, "blocked_ips.json")
	
	blockedIPsMutex.RLock()
	data, err := json.Marshal(blockedIPs)
	blockedIPsMutex.RUnlock()
	
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0600)
}

// BlockIP blocks an IP address
func BlockIP(ip string, cfg *config.Config) error {
	if !isValidIP(ip) {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check whitelist
	for _, whitelisted := range cfg.Whitelist {
		if whitelisted == ip {
			return fmt.Errorf("cannot block whitelisted IP: %s", ip)
		}
	}

	expiry := time.Now().Add(cfg.BlockDuration)
	
	blockedIPsMutex.Lock()
	blockedIPs[ip] = expiry
	blockedIPsMutex.Unlock()

	if err := addToIPSet(ip, cfg.BlockDuration); err != nil {
		return fmt.Errorf("failed to add IP to ipset: %w", err)
	}

	if err := saveBlockedIPs(cfg); err != nil {
		log.Printf("Warning: failed to save blocked IPs: %v", err)
	}

	statsMutex.Lock()
	stats.ActiveBlocks++
	statsMutex.Unlock()
	activeBlocks.Set(float64(stats.ActiveBlocks))

	log.Printf("Blocked IP: %s until %s", ip, expiry.Format(time.RFC3339))
	return nil
}

// UnblockIP unblocks an IP address
func UnblockIP(ip string, cfg *config.Config) error {
	if !isValidIP(ip) {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	if err := removeFromIPSet(ip); err != nil {
		return fmt.Errorf("failed to remove IP from ipset: %w", err)
	}

	blockedIPsMutex.Lock()
	delete(blockedIPs, ip)
	blockedIPsMutex.Unlock()

	if err := saveBlockedIPs(cfg); err != nil {
		log.Printf("Warning: failed to save blocked IPs: %v", err)
	}

	statsMutex.Lock()
	if stats.ActiveBlocks > 0 {
		stats.ActiveBlocks--
	}
	statsMutex.Unlock()
	activeBlocks.Set(float64(stats.ActiveBlocks))

	log.Printf("Unblocked IP: %s", ip)
	return nil
}

// ListBlocked lists all blocked IPs
func ListBlocked(cfg *config.Config) error {
	blockedIPsMutex.RLock()
	defer blockedIPsMutex.RUnlock()

	if len(blockedIPs) == 0 {
		fmt.Println("No blocked IPs")
		return nil
	}

	fmt.Printf("%-20s %-30s\n", "IP Address", "Expires At")
	fmt.Println(strings.Repeat("-", 50))
	
	for ip, expiry := range blockedIPs {
		if expiry.IsZero() {
			fmt.Printf("%-20s %-30s\n", ip, "Permanent")
		} else {
			fmt.Printf("%-20s %-30s\n", ip, expiry.Format(time.RFC3339))
		}
	}

	return nil
}

// ShowStats displays firewall statistics
func ShowStats(cfg *config.Config) error {
	statsMutex.RLock()
	s := stats
	statsMutex.RUnlock()

	blockedIPsMutex.RLock()
	activeCount := len(blockedIPs)
	blockedIPsMutex.RUnlock()

	output := fmt.Sprintf(`
Luveedu Firewall Statistics
===========================
Start Time:        %s
Uptime:            %s
Total Requests:    %d
Blocked Requests:  %d
Active Blocks:     %d
`,
		s.StartTime.Format(time.RFC3339),
		time.Since(s.StartTime).Round(time.Second),
		s.TotalRequests,
		s.BlockedRequests,
		activeCount,
	)

	fmt.Println(output)
	return nil
}

// CheckRateLimit checks if an IP exceeds rate limits
func CheckRateLimit(ip string, cfg *config.Config) bool {
	if !cfg.RateLimit.Enabled {
		return false
	}

	now := time.Now()
	window := cfg.RateLimit.SustainedWindow
	limit := cfg.RateLimit.SustainedLimit

	requestCountsMutex.Lock()
	defer requestCountsMutex.Unlock()

	// Get or create timestamp list for this IP
	timestamps, exists := requestCounts[ip]
	if !exists {
		timestamps = []time.Time{}
	}

	// Remove old timestamps outside the window
	cutoff := now.Add(-window)
	validTimestamps := []time.Time{}
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			validTimestamps = append(validTimestamps, ts)
		}
	}

	// Add current request
	validTimestamps = append(validTimestamps, now)
	requestCounts[ip] = validTimestamps

	// Check if limit exceeded
	if len(validTimestamps) > limit {
		return true
	}

	return false
}

// StartEventLoop starts the main event processing loop
func StartEventLoop(cfg *config.Config) error {
	log.Printf("Starting event loop...")

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			cleanupExpiredBlocks(cfg)
			cleanupOldRequestCounts()
		}
	}()

	// Start log monitoring if enabled
	if cfg.WAF.Enabled {
		go monitorAccessLogs(cfg)
	}

	// Block forever
	select {}
}

// StartLogMonitor starts the log monitoring daemon
func StartLogMonitor(cfg *config.Config) error {
	log.Printf("Starting log monitor...")

	// Monitor syslog
	go monitorSyslog(cfg)

	// Block forever
	select {}
}

// cleanupExpiredBlocks removes expired IP blocks
func cleanupExpiredBlocks(cfg *config.Config) {
	now := time.Now()
	var toRemove []string

	blockedIPsMutex.Lock()
	for ip, expiry := range blockedIPs {
		if !expiry.IsZero() && expiry.Before(now) {
			toRemove = append(toRemove, ip)
		}
	}
	for _, ip := range toRemove {
		delete(blockedIPs, ip)
	}
	blockedIPsMutex.Unlock()

	for _, ip := range toRemove {
		removeFromIPSet(ip)
	}

	if len(toRemove) > 0 {
		saveBlockedIPs(cfg)
		
		statsMutex.Lock()
		stats.ActiveBlocks -= len(toRemove)
		statsMutex.Unlock()
		activeBlocks.Set(float64(stats.ActiveBlocks))
	}
}

// cleanupOldRequestCounts removes old request count entries
func cleanupOldRequestCounts() {
	now := time.Now()
	maxAge := 30 * time.Second

	requestCountsMutex.Lock()
	defer requestCountsMutex.Unlock()

	for ip := range requestCounts {
		delete(requestCounts, ip)
	}
}

// monitorAccessLogs monitors web server access logs
func monitorAccessLogs(cfg *config.Config) {
	logPaths := []string{
		"/var/log/openlitespeed/*.log",
		"/var/log/nginx/*.log",
		"/var/log/apache2/*.log",
		"/var/log/httpd/*.log",
	}

	for _, pattern := range logPaths {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, path := range matches {
			go watchLogFile(path, cfg)
		}
	}
}

// watchLogFile watches a single log file
func watchLogFile(path string, cfg *config.Config) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("Failed to open log file %s: %v", path, err)
		return
	}
	defer file.Close()

	// Seek to end
	file.Seek(0, 2)

	scanner := bufio.NewScanner(file)
	ipRegex := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+`)

	for {
		// Simple tail implementation
		time.Sleep(100 * time.Millisecond)
		
		// Reopen file to check for new content
		newFile, err := os.Open(path)
		if err != nil {
			continue
		}
		
		stat, err := newFile.Stat()
		if err != nil {
			newFile.Close()
			continue
		}
		
		if stat.Size() < file.Seek(0, 1) {
			// File was rotated
			file.Close()
			file = newFile
			scanner = bufio.NewScanner(file)
		} else {
			newFile.Close()
		}

		for scanner.Scan() {
			line := scanner.Text()
			ip := ipRegex.FindString(line)
			if ip != "" {
				processRequest(ip, line, cfg)
			}
		}
	}
}

// processRequest processes a single request from log
func processRequest(ip, line string, cfg *config.Config) {
	statsMutex.Lock()
	stats.TotalRequests++
	statsMutex.Unlock()
	totalRequests.Inc()

	// Check rate limit
	if CheckRateLimit(ip, cfg) {
		BlockIP(ip, cfg)
		
		statsMutex.Lock()
		stats.BlockedRequests++
		statsMutex.Unlock()
		blockedRequests.Inc()
		
		log.Printf("Blocked %s due to rate limiting", ip)
		return
	}

	// Check for malicious patterns
	if isMaliciousRequest(line, cfg) {
		BlockIP(ip, cfg)
		
		statsMutex.Lock()
		stats.BlockedRequests++
		statsMutex.Unlock()
		blockedRequests.Inc()
		
		log.Printf("Blocked %s due to malicious request", ip)
	}
}

// isMaliciousRequest checks if a request contains malicious patterns
func isMaliciousRequest(line string, cfg *config.Config) bool {
	if !cfg.WAF.Enabled {
		return false
	}

	maliciousPatterns := []string{
		"(?i)(union\\s+select)",
		"(?i)(select\\s+.*\\s+from)",
		"(?i)(insert\\s+into)",
		"(?i)(drop\\s+table)",
		"(?i)(<script[^>]*>)",
		"(?i)(javascript:)",
		"(?i)(\\.\\./)",
		"(?i)(/etc/passwd)",
		"(?i)(cmd=|exec=|system\\()",
		"(?i)(eval\\(|base64_decode)",
	}

	for _, pattern := range maliciousPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			return true
		}
	}

	return false
}

// monitorSyslog monitors system logs for security events
func monitorSyslog(cfg *config.Config) {
	syslogPaths := []string{
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/auth.log",
		"/var/log/secure",
	}

	for _, path := range syslogPaths {
		if _, err := os.Stat(path); err == nil {
			go watchSyslogFile(path, cfg)
		}
	}
}

// watchSyslogFile watches a syslog file
func watchSyslogFile(path string, cfg *config.Config) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	file.Seek(0, 2)
	scanner := bufio.NewScanner(file)

	// Patterns indicating attacks
	attackPatterns := []string{
		`Failed password`,
		`Invalid user`,
		`Connection closed by authenticating user`,
		`POSSIBLE BREAK-IN ATTEMPT`,
		`port scan detected`,
	}

	ipRegex := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)

	for {
		time.Sleep(100 * time.Millisecond)
		
		newFile, err := os.Open(path)
		if err != nil {
			continue
		}
		
		stat, err := newFile.Stat()
		if err != nil {
			newFile.Close()
			continue
		}
		
		if stat.Size() < file.Seek(0, 1) {
			file.Close()
			file = newFile
			scanner = bufio.NewScanner(file)
		} else {
			newFile.Close()
		}

		for scanner.Scan() {
			line := scanner.Text()
			
			for _, pattern := range attackPatterns {
				if strings.Contains(line, pattern) {
					ips := ipRegex.FindAllString(line, -1)
					for _, ip := range ips {
						if !isWhitelisted(ip, cfg) {
							BlockIP(ip, cfg)
							log.Printf("Blocked %s due to security event in syslog", ip)
						}
					}
					break
				}
			}
		}
	}
}

// isWhitelisted checks if an IP is whitelisted
func isWhitelisted(ip string, cfg *config.Config) bool {
	for _, whitelisted := range cfg.Whitelist {
		if whitelisted == ip {
			return true
		}
	}
	return false
}

// addToIPSet adds an IP to the blacklist ipset
func addToIPSet(ip string, duration time.Duration) error {
	timeout := int(duration.Seconds())
	if duration == 0 {
		timeout = 0
	}
	
	cmd := exec.Command("ipset", "add", "luvd_blacklist", ip, "timeout", strconv.Itoa(timeout))
	return cmd.Run()
}

// removeFromIPSet removes an IP from the blacklist ipset
func removeFromIPSet(ip string) error {
	cmd := exec.Command("ipset", "del", "luvd_blacklist", ip)
	return cmd.Run()
}

// isValidIP validates an IP address
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// Cleanup performs cleanup on shutdown
func Cleanup() {
	log.Printf("Performing cleanup...")
	
	// Save state
	cfg := config.Default()
	saveBlockedIPs(cfg)
	
	log.Printf("Cleanup completed")
}
