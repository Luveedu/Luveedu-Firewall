package engine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"luveedu/config"
)

// RateLimiter tracks request rates per IP
type RateLimiter struct {
	mu       sync.RWMutex
	requests map[string][]time.Time
	cfg      *config.Config
}

// Blocker manages IP blocking via ipset/iptables
type Blocker struct {
	cfg       *config.Config
	blockedIPs map[string]time.Time
	mu         sync.RWMutex
}

// LogParser parses web server access logs
type LogParser struct {
	logPattern *regexp.Regexp
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(cfg *config.Config) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		cfg:      cfg,
	}
}

// NewBlocker creates a new IP blocker
func NewBlocker(cfg *config.Config) *Blocker {
	return &Blocker{
		blockedIPs: make(map[string]time.Time),
		cfg:        cfg,
	}
}

// NewLogParser creates a log parser for common log formats
func NewLogParser() *LogParser {
	// Matches: IP - - [timestamp] "METHOD PATH PROTO" status size
	return &LogParser{
		logPattern: regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\s+\S+\s+\S+\s+\[.*?\]\s+"[A-Z]+\s+(\S+)\s+[^"]*"`),
	}
}

// CheckRateLimit checks if an IP exceeds rate limits
// Returns true if the IP should be blocked
func (rl *RateLimiter) CheckRateLimit(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowBurst := now.Add(-3 * time.Second)
	windowSustain := now.Add(-30 * time.Second)

	// Filter old requests
	var recentBurst, recentSustain []time.Time
	for _, t := range rl.requests[ip] {
		if t.After(windowSustain) {
			recentSustain = append(recentSustain, t)
		}
		if t.After(windowBurst) {
			recentBurst = append(recentBurst, t)
		}
	}

	// Add current request
	recentBurst = append(recentBurst, now)
	recentSustain = append(recentSustain, now)

	rl.requests[ip] = recentSustain

	// Check burst limit (15 req/3s)
	if len(recentBurst) > rl.cfg.RateLimitBurst {
		return true
	}

	// Check sustain limit (150 req/30s)
	if len(recentSustain) > rl.cfg.RateLimitSustain {
		return true
	}

	return false
}

// CleanupOldRequests removes old request records to prevent memory leaks
func (rl *RateLimiter) CleanupOldRequests() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-60 * time.Second)
	for ip, times := range rl.requests {
		var kept []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = kept
		}
	}
}

// IsWhitelisted checks if an IP is in the whitelist
func (b *Blocker) IsWhitelisted(ip string) bool {
	for _, wip := range b.cfg.Whitelist {
		if wip == ip {
			return true
		}
	}
	return false
}

// BlockIP adds an IP to the blocklist using ipset
func (b *Blocker) BlockIP(ip string, duration time.Duration) error {
	if b.IsWhitelisted(ip) {
		return fmt.Errorf("cannot block whitelisted IP: %s", ip)
	}

	// Validate IP
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	b.mu.Lock()
	b.blockedIPs[ip] = time.Now().Add(duration)
	b.mu.Unlock()

	// Add to ipset
	cmd := exec.Command("ipset", "add", b.cfg.IPSetname, ip, "timeout", fmt.Sprintf("%d", int(duration.Seconds())))
	if err := cmd.Run(); err != nil {
		// Fallback to iptables if ipset fails
		cmd = exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
		if err2 := cmd.Run(); err2 != nil {
			return fmt.Errorf("failed to block IP %s: %v (fallback also failed: %v)", ip, err, err2)
		}
	}

	return nil
}

// UnblockIP removes an IP from the blocklist
func (b *Blocker) UnblockIP(ip string) error {
	b.mu.Lock()
	delete(b.blockedIPs, ip)
	b.mu.Unlock()

	// Remove from ipset
	cmd := exec.Command("ipset", "del", b.cfg.IPSetname, ip)
	if err := cmd.Run(); err != nil {
		// Try iptables fallback
		cmd = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
		if err2 := cmd.Run(); err2 != nil {
			return fmt.Errorf("failed to unblock IP %s: %v (fallback also failed: %v)", ip, err, err2)
		}
	}

	return nil
}

// GetBlockedIPs returns list of currently blocked IPs
func (b *Blocker) GetBlockedIPs() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var ips []string
	now := time.Now()
	for ip, expiry := range b.blockedIPs {
		if expiry.After(now) {
			ips = append(ips, ip)
		}
	}
	return ips
}

// ParseLogLine extracts IP and path from a log line
func (lp *LogParser) ParseLogLine(line string) (ip, path string, ok bool) {
	matches := lp.logPattern.FindStringSubmatch(line)
	if len(matches) >= 3 {
		return matches[1], matches[2], true
	}
	return "", "", false
}

// MonitorLogs continuously monitors log file for attacks
func MonitorLogs(ctx context.Context, cfg *config.Config, rl *RateLimiter, blocker *Blocker, parser *LogParser) error {
	file, err := os.Open(cfg.LogFile)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	defer file.Close()

	// Seek to end of file
	file.Seek(0, 2)

	scanner := bufio.NewScanner(file)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Cleanup old requests periodically
			rl.CleanupOldRequests()
			
			// Reopen file to handle log rotation
			file.Close()
			file, err = os.Open(cfg.LogFile)
			if err != nil {
				continue
			}
			file.Seek(0, 2)
			scanner = bufio.NewScanner(file)
		default:
			if scanner.Scan() {
				line := scanner.Text()
				ip, path, ok := parser.ParseLogLine(line)
				if !ok {
					continue
				}

				// Check for malicious patterns in path
				if isMaliciousPath(path) {
					if err := blocker.BlockIP(ip, cfg.BlockDuration); err != nil {
						fmt.Printf("Failed to block malicious IP %s: %v\n", ip, err)
					}
					continue
				}

				// Check rate limit
				if rl.CheckRateLimit(ip) {
					if err := blocker.BlockIP(ip, cfg.BlockDuration); err != nil {
						fmt.Printf("Failed to block rate-limited IP %s: %v\n", ip, err)
					}
				}
			}
		}
	}
}

// isMaliciousPath checks for common attack patterns in URL paths
func isMaliciousPath(path string) bool {
	maliciousPatterns := []string{
		`\.php\?`,
		`wp-admin`,
		`wp-login`,
		`xmlrpc\.php`,
		`\.\./`,
		`etc/passwd`,
		`cmd=`,
		`exec=`,
		`shell`,
		`eval\(`,
		`<script`,
		`union\s+select`,
		`drop\s+table`,
	}

	pathLower := strings.ToLower(path)
	for _, pattern := range maliciousPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}

// InitIPSet initializes the ipset for blocking
func InitIPSet(cfg *config.Config) error {
	// Flush existing set if any
	exec.Command("ipset", "destroy", cfg.IPSetname).Run()

	// Create new hash:ip set
	cmd := exec.Command("ipset", "create", cfg.IPSetname, "hash:ip", "timeout", "3600", "-exist")
	return cmd.Run()
}

// EnsureIPTablesRule ensures iptables rule references ipset
func EnsureIPTablesRule(cfg *config.Config) error {
	// Check if rule exists
	checkCmd := exec.Command("iptables", "-C", "INPUT", "-m", "set", "--match-set", cfg.IPSetname, "src", "-j", "DROP")
	if err := checkCmd.Run(); err == nil {
		return nil // Rule already exists
	}

	// Add rule
	cmd := exec.Command("iptables", "-I", "INPUT", "-m", "set", "--match-set", cfg.IPSetname, "src", "-j", "DROP")
	return cmd.Run()
}
