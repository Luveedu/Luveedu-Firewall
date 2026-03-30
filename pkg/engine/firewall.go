package engine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luveedu/luvd-firewall/pkg/config"
)

// RateLimiter handles IP rate limiting with dual-window algorithm
type RateLimiter struct {
	config      *config.RateLimitConfig
	burstWindow map[string][]time.Time
	sustainedWindow map[string][]time.Time
	mu          sync.RWMutex
	blockedList map[string]time.Time
	ipsetAvailable bool
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(cfg *config.RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		config:        cfg,
		burstWindow:   make(map[string][]time.Time),
		sustainedWindow: make(map[string][]time.Time),
		blockedList:   make(map[string]time.Time),
		ipsetAvailable: checkIPSetAvailability(),
	}
	
	// Start cleanup goroutine
	go rl.cleanupLoop()
	
	return rl
}

// checkIPSetAvailability checks if ipset command is available
func checkIPSetAvailability() bool {
	cmd := exec.Command("ipset", "-v")
	return cmd.Run() == nil
}

// CheckAndBlock checks if an IP should be blocked and blocks it if necessary
func (rl *RateLimiter) CheckAndBlock(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	// Check if already blocked
	if blockTime, exists := rl.blockedList[ip]; exists {
		if now.Before(blockTime) {
			return true // Still blocked
		}
		delete(rl.blockedList, ip)
	}
	
	// Clean old entries from windows
	rl.cleanWindow(rl.burstWindow[ip], now.Add(-rl.config.BurstWindow))
	rl.cleanWindow(rl.sustainedWindow[ip], now.Add(-rl.config.SustainedWindow))
	
	// Add current request
	rl.burstWindow[ip] = append(rl.burstWindow[ip], now)
	rl.sustainedWindow[ip] = append(rl.sustainedWindow[ip], now)
	
	// Check burst limit
	if len(rl.burstWindow[ip]) > rl.config.BurstLimit {
		rl.blockIP(ip)
		return true
	}
	
	// Check sustained limit
	if len(rl.sustainedWindow[ip]) > rl.config.SustainedLimit {
		rl.blockIP(ip)
		return true
	}
	
	return false
}

func (rl *RateLimiter) cleanWindow(window []time.Time, cutoff time.Time) []time.Time {
	var cleaned []time.Time
	for _, t := range window {
		if t.After(cutoff) {
			cleaned = append(cleaned, t)
		}
	}
	return cleaned
}

func (rl *RateLimiter) blockIP(ip string) {
	blockUntil := time.Now().Add(rl.config.BlockDuration)
	rl.blockedList[ip] = blockUntil
	
	// Block using iptables/ipset
	if rl.ipsetAvailable {
		rl.blockWithIPSet(ip)
	} else {
		rl.blockWithIptables(ip)
	}
}

func (rl *RateLimiter) blockWithIPSet(ip string) {
	ipsetName := "luvd-blocklist"
	
	// Create ipset if not exists
	exec.Command("ipset", "create", ipsetName, "hash:ip", "timeout", "3600").Run()
	
	// Add IP to ipset
	exec.Command("ipset", "add", ipsetName, ip, "timeout", strconv.Itoa(int(rl.config.BlockDuration.Seconds()))).Run()
}

func (rl *RateLimiter) blockWithIptables(ip string) {
	// Add iptables rule with timeout
	exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "luvd-block").Run()
	
	// Schedule removal
	go func() {
		time.Sleep(rl.config.BlockDuration)
		exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "luvd-block").Run()
	}()
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		
		// Clean expired blocks
		for ip, blockTime := range rl.blockedList {
			if now.After(blockTime) {
				delete(rl.blockedList, ip)
			}
		}
		
		// Clean old window entries
		cutoff := now.Add(-rl.config.SustainedWindow)
		for ip := range rl.burstWindow {
			rl.burstWindow[ip] = rl.cleanWindow(rl.burstWindow[ip], cutoff)
			if len(rl.burstWindow[ip]) == 0 {
				delete(rl.burstWindow, ip)
			}
		}
		for ip := range rl.sustainedWindow {
			rl.sustainedWindow[ip] = rl.cleanWindow(rl.sustainedWindow[ip], cutoff)
			if len(rl.sustainedWindow[ip]) == 0 {
				delete(rl.sustainedWindow, ip)
			}
		}
		
		rl.mu.Unlock()
	}
}

// LogParser parses web server access logs
type LogParser struct {
	logPath   string
	pattern   *regexp.Regexp
	ctx       context.Context
	cancel    context.CancelFunc
}

// LogEntry represents a parsed log entry
type LogEntry struct {
	IP         string
	Timestamp  time.Time
	Method     string
	Path       string
	Status     int
	UserAgent  string
	BytesSent  int
	RawLine    string
}

// NewLogParser creates a new log parser
func NewLogParser(logPath string) *LogParser {
	// Common Log Format / Combined Log Format pattern
	pattern := regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) (\d+|-) "[^"]*" "([^"]*)"`)
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &LogParser{
		logPath:  logPath,
		pattern:  pattern,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// ParseLine parses a single log line
func (lp *LogParser) ParseLine(line string) (*LogEntry, error) {
	matches := lp.pattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("failed to parse log line")
	}
	
	// Parse timestamp
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])
	if err != nil {
		return nil, err
	}
	
	// Parse status code
	status, _ := strconv.Atoi(matches[5])
	
	// Parse bytes sent
	bytesSent := 0
	if matches[6] != "-" {
		bytesSent, _ = strconv.Atoi(matches[6])
	}
	
	return &LogEntry{
		IP:        matches[1],
		Timestamp: timestamp,
		Method:    matches[3],
		Path:      matches[4],
		Status:    status,
		UserAgent: matches[7],
		BytesSent: bytesSent,
		RawLine:   line,
	}, nil
}

// TailFile tails the log file and sends entries to a channel
func (lp *LogParser) TailFile() (<-chan *LogEntry, error) {
	entries := make(chan *LogEntry, 1000)
	
	go func() {
		defer close(entries)
		
		for {
			select {
			case <-lp.ctx.Done():
				return
			default:
				lp.tailAndProcess(entries)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	
	return entries, nil
}

func (lp *LogParser) tailAndProcess(entries chan<- *LogEntry) {
	cmd := exec.CommandContext(lp.ctx, "tail", "-F", "-n", "0", lp.logPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	
	if err := cmd.Start(); err != nil {
		return
	}
	defer cmd.Wait()
	
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		entry, err := lp.ParseLine(line)
		if err == nil {
			entries <- entry
		}
	}
}

// Stop stops the log parser
func (lp *LogParser) Stop() {
	lp.cancel()
}

// FirewallEngine is the main firewall engine
type FirewallEngine struct {
	config     *config.Config
	rateLimiter *RateLimiter
	logParser  *LogParser
	stats      FirewallStats
	mu         sync.RWMutex
}

// FirewallStats holds firewall statistics
type FirewallStats struct {
	TotalRequests   int64
	BlockedRequests int64
	UniqueIPs       int
	StartTime       time.Time
}

// NewFirewallEngine creates a new firewall engine
func NewFirewallEngine(cfg *config.Config) *FirewallEngine {
	return &FirewallEngine{
		config:      cfg,
		rateLimiter: NewRateLimiter(&cfg.RateLimit),
		stats: FirewallStats{
			StartTime: time.Now(),
		},
	}
}

// Start starts the firewall engine
func (fe *FirewallEngine) Start(ctx context.Context) error {
	// Initialize ipset
	if fe.config.Network.UseIPSet {
		fe.initializeIPSet()
	}
	
	// Start log parsing
	fe.logParser = NewLogParser(fe.config.LogFile)
	entries, err := fe.logParser.TailFile()
	if err != nil {
		return err
	}
	
	go fe.processEntries(ctx, entries)
	
	return nil
}

func (fe *FirewallEngine) initializeIPSet() {
	ipsetName := fe.config.Network.IPSetName
	
	// Flush existing set
	exec.Command("ipset", "destroy", ipsetName).Run()
	
	// Create new set
	exec.Command("ipset", "create", ipsetName, "hash:ip", "timeout", "3600").Run()
}

func (fe *FirewallEngine) processEntries(ctx context.Context, entries <-chan *LogEntry) {
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-entries:
			if !ok {
				return
			}
			
			fe.processEntry(entry)
		}
	}
}

func (fe *FirewallEngine) processEntry(entry *LogEntry) {
	fe.mu.Lock()
	fe.stats.TotalRequests++
	fe.mu.Unlock()
	
	// Check rate limiting
	if fe.config.RateLimit.Enabled {
		if fe.rateLimiter.CheckAndBlock(entry.IP) {
			fe.mu.Lock()
			fe.stats.BlockedRequests++
			fe.mu.Unlock()
			
			// Log blocked request
			fmt.Printf("[BLOCKED] %s - %s %s (Rate Limit Exceeded)\n", 
				entry.IP, entry.Method, entry.Path)
			return
		}
	}
	
	// Additional processing can be added here
	// (WAF checks, threat intelligence, etc.)
}

// GetStats returns current firewall statistics
func (fe *FirewallEngine) GetStats() FirewallStats {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return fe.stats
}

// Stop stops the firewall engine
func (fe *FirewallEngine) Stop() {
	if fe.logParser != nil {
		fe.logParser.Stop()
	}
}

// BlockIP manually blocks an IP address
func (fe *FirewallEngine) BlockIP(ip string, duration time.Duration) error {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	
	if fe.config.Network.UseIPSet {
		ipsetName := fe.config.Network.IPSetName
		timeout := int(duration.Seconds())
		cmd := exec.Command("ipset", "add", ipsetName, ip, "timeout", strconv.Itoa(timeout))
		return cmd.Run()
	}
	
	// Fallback to iptables
	cmd := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	return cmd.Run()
}

// UnblockIP manually unblocks an IP address
func (fe *FirewallEngine) UnblockIP(ip string) error {
	if fe.config.Network.UseIPSet {
		ipsetName := fe.config.Network.IPSetName
		cmd := exec.Command("ipset", "del", ipsetName, ip)
		return cmd.Run()
	}
	
	// Fallback to iptables
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	return cmd.Run()
}

// ListBlockedIPs returns a list of currently blocked IPs
func (fe *FirewallEngine) ListBlockedIPs() ([]string, error) {
	if !fe.config.Network.UseIPSet {
		return []string{}, nil
	}
	
	ipsetName := fe.config.Network.IPSetName
	cmd := exec.Command("ipset", "list", ipsetName, "-n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	
	var ips []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" && !strings.HasPrefix(ip, "#") {
			ips = append(ips, ip)
		}
	}
	
	return ips, nil
}
