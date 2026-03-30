package waf

import (
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/luveedu/luvd-firewall/pkg/config"
)

// WAFEngine is the Web Application Firewall engine
type WAFEngine struct {
	config     *config.WAFConfig
	rules      []WAFRule
	sqlPatterns []*regexp.Regexp
	xssPatterns []*regexp.Regexp
	pathPatterns []*regexp.Regexp
	rcePatterns []*regexp.Regexp
	mu         sync.RWMutex
}

// WAFRule represents a WAF rule
type WAFRule struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Action      string // block, log, alert
	Description string
	Enabled     bool
	Category    string // sql_injection, xss, path_traversal, rce, file_inclusion
}

// WAFRequest represents a request to be analyzed
type WAFRequest struct {
	Method      string
	Path        string
	Query       string
	Headers     http.Header
	Body        string
	RemoteAddr  string
	UserAgent   string
}

// WAFResult represents the result of WAF analysis
type WAFResult struct {
	Blocked     bool
	RuleID      string
	RuleName    string
	Category    string
	Description string
	Score       int
}

// NewWAFEngine creates a new WAF engine
func NewWAFEngine(cfg *config.WAFConfig) *WAFEngine {
	waf := &WAFEngine{
		config: cfg,
		rules:  make([]WAFRule, 0),
	}
	
	waf.initializePatterns()
	waf.loadDefaultRules()
	
	return waf
}

func (w *WAFEngine) initializePatterns() {
	// SQL Injection patterns
	sqlPatterns := []string{
		`(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b)`,
		`(?i)(\b(OR|AND)\b\s+\d+\s*=\s*\d+)`,
		`(?i)(\b(OR|AND)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)`,
		`(?i)(--|#|/\*)`,
		`(?i)(\b(WAITFOR|BENCHMARK|SLEEP)\b)`,
		`(?i)(\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b)`,
		`(?i)(\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b)`,
	}
	
	for _, pattern := range sqlPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			w.sqlPatterns = append(w.sqlPatterns, re)
		}
	}
	
	// XSS patterns
	xssPatterns := []string{
		`(?i)(<script[^>]*>)`,
		`(?i)(</script>)`,
		`(?i)(javascript:)`,
		`(?i)(on(load|error|click|mouse|focus|blur|change|submit|reset|select|abort|keydown|keypress|keyup|unload|resize|scroll|dblclick|drag|drop)\s*=)`,
		`(?i)(<iframe[^>]*>)`,
		`(?i)(<object[^>]*>)`,
		`(?i)(<embed[^>]*>)`,
		`(?i)(<svg[^>]*>)`,
		`(?i)(document\.(cookie|write|writeln|location))`,
		`(?i)(window\.(location|open|close|alert))`,
		`(?i)(eval\s*\()`,
		`(?i)(alert\s*\()`,
		`(?i)(prompt\s*\()`,
		`(?i)(confirm\s*\()`,
	}
	
	for _, pattern := range xssPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			w.xssPatterns = append(w.xssPatterns, re)
		}
	}
	
	// Path traversal patterns
	pathPatterns := []string{
		`(\.\./)`,
		`(\.\.\\)`,
		`(%2e%2e%2f)`,
		`(%2e%2e/)`,
		`(\.\.%2f)`,
		`(%2e%2e\\)`,
		`(/etc/passwd)`,
		`(/etc/shadow)`,
		`(/proc/self)`,
		`(c:\\windows)`,
		`(file://)`,
		`(phar://)`,
		`(zip://)`,
		`(data://)`,
		`(expect://)`,
	}
	
	for _, pattern := range pathPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			w.pathPatterns = append(w.pathPatterns, re)
		}
	}
	
	// RCE patterns
	rcePatterns := []string{
		`(?i)(\b(exec|execute|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\b)`,
		`(?i)(\b(eval|assert|preg_replace)\s*\()`,
		`(?i)(\b(cmd|powershell|bash|sh|zsh|csh|ksh|tcsh)\b)`,
		`(?i)(\|.*\b(cat|ls|dir|whoami|id|uname|pwd|wget|curl|nc|netcat)\b)`,
		`(?i)(` + "`" + `[^` + "`" + `]*` + "`" + `)`, // Backtick execution
		`(?i)(\$\([^)]+\))`, // Command substitution
		`(?i)(\b(import|__import__|os\.|sys\.)\b)`, // Python specific
		`(?i)(\b(Runtime\.getRuntime)\b)`, // Java specific
	}
	
	for _, pattern := range rcePatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			w.rcePatterns = append(w.rcePatterns, re)
		}
	}
}

func (w *WAFEngine) loadDefaultRules() {
	// SQL Injection rules
	if w.config.DetectSQLInjection {
		w.rules = append(w.rules, WAFRule{
			ID:          "SQLI-001",
			Name:        "SQL Injection - Common Keywords",
			Pattern:     regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)`),
			Action:      "block",
			Description: "Detected SQL injection attempt with common SQL keywords",
			Enabled:     true,
			Category:    "sql_injection",
		})
		
		w.rules = append(w.rules, WAFRule{
			ID:          "SQLI-002",
			Name:        "SQL Injection - Boolean Based",
			Pattern:     regexp.MustCompile(`(?i)(OR\s+\d+\s*=\s*\d+|AND\s+\d+\s*=\s*\d+)`),
			Action:      "block",
			Description: "Detected boolean-based SQL injection attempt",
			Enabled:     true,
			Category:    "sql_injection",
		})
		
		w.rules = append(w.rules, WAFRule{
			ID:          "SQLI-003",
			Name:        "SQL Injection - Comment Injection",
			Pattern:     regexp.MustCompile(`(--|#|/\*)`),
			Action:      "block",
			Description: "Detected SQL comment injection attempt",
			Enabled:     true,
			Category:    "sql_injection",
		})
	}
	
	// XSS rules
	if w.config.DetectXSS {
		w.rules = append(w.rules, WAFRule{
			ID:          "XSS-001",
			Name:        "XSS - Script Tag",
			Pattern:     regexp.MustCompile(`(?i)(<script[^>]*>|</script>)`),
			Action:      "block",
			Description: "Detected XSS attempt with script tags",
			Enabled:     true,
			Category:    "xss",
		})
		
		w.rules = append(w.rules, WAFRule{
			ID:          "XSS-002",
			Name:        "XSS - JavaScript Protocol",
			Pattern:     regexp.MustCompile(`(?i)(javascript:)`),
			Action:      "block",
			Description: "Detected XSS attempt with javascript: protocol",
			Enabled:     true,
			Category:    "xss",
		})
		
		w.rules = append(w.rules, WAFRule{
			ID:          "XSS-003",
			Name:        "XSS - Event Handler",
			Pattern:     regexp.MustCompile(`(?i)(on(load|error|click|mouse)\s*=)`),
			Action:      "block",
			Description: "Detected XSS attempt with event handler",
			Enabled:     true,
			Category:    "xss",
		})
	}
	
	// Path traversal rules
	if w.config.DetectPathTraversal {
		w.rules = append(w.rules, WAFRule{
			ID:          "PATH-001",
			Name:        "Path Traversal - Directory Traversal",
			Pattern:     regexp.MustCompile(`(\.\./|\.\.\\)`),
			Action:      "block",
			Description: "Detected path traversal attempt",
			Enabled:     true,
			Category:    "path_traversal",
		})
		
		w.rules = append(w.rules, WAFRule{
			ID:          "PATH-002",
			Name:        "Path Traversal - Sensitive Files",
			Pattern:     regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|c:\\windows)`),
			Action:      "block",
			Description: "Detected attempt to access sensitive files",
			Enabled:     true,
			Category:    "path_traversal",
		})
	}
	
	// RCE rules
	if w.config.DetectRCE {
		w.rules = append(w.rules, WAFRule{
			ID:          "RCE-001",
			Name:        "RCE - Command Execution Functions",
			Pattern:     regexp.MustCompile(`(?i)(exec|system|passthru|shell_exec)`),
			Action:      "block",
			Description: "Detected potential remote code execution attempt",
			Enabled:     true,
			Category:    "rce",
		})
		
		w.rules = append(w.rules, WAFRule{
			ID:          "RCE-002",
			Name:        "RCE - Eval/Assert",
			Pattern:     regexp.MustCompile(`(?i)(eval|assert)\s*\(`),
			Action:      "block",
			Description: "Detected eval/assert code execution attempt",
			Enabled:     true,
			Category:    "rce",
		})
	}
	
	// File inclusion rules
	if w.config.DetectFileInclusion {
		w.rules = append(w.rules, WAFRule{
			ID:          "LFI-001",
			Name:        "Local File Inclusion",
			Pattern:     regexp.MustCompile(`(?i)(file://|phar://|zip://|data://)`),
			Action:      "block",
			Description: "Detected local file inclusion attempt",
			Enabled:     true,
			Category:    "file_inclusion",
		})
		
		w.rules = append(w.rules, WAFRule{
			ID:          "RFI-001",
			Name:        "Remote File Inclusion",
			Pattern:     regexp.MustCompile(`(?i)(https?://.*\.(php|jsp|asp|aspx))`),
			Action:      "block",
			Description: "Detected remote file inclusion attempt",
			Enabled:     true,
			Category:    "file_inclusion",
		})
	}
}

// Analyze analyzes a request and returns the result
func (w *WAFEngine) Analyze(req *WAFRequest) *WAFResult {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	result := &WAFResult{
		Blocked: false,
		Score:   0,
	}
	
	// Combine all inputs to check
	inputs := []string{
		req.Path,
		req.Query,
		req.Body,
		req.UserAgent,
	}
	
	fullInput := strings.Join(inputs, " ")
	
	// Check against all rules
	for _, rule := range w.rules {
		if !rule.Enabled {
			continue
		}
		
		if rule.Pattern.MatchString(fullInput) {
			result.Blocked = true
			result.RuleID = rule.ID
			result.RuleName = rule.Name
			result.Category = rule.Category
			result.Description = rule.Description
			result.Score += 10
			
			if rule.Action == "block" {
				return result
			}
		}
	}
	
	// Additional pattern-based checks
	if w.checkSQLInjection(fullInput) {
		result.Blocked = true
		result.RuleID = "SQLI-PATTERN"
		result.RuleName = "SQL Injection Pattern Match"
		result.Category = "sql_injection"
		result.Description = "Detected SQL injection pattern"
		result.Score += 20
		return result
	}
	
	if w.checkXSS(fullInput) {
		result.Blocked = true
		result.RuleID = "XSS-PATTERN"
		result.RuleName = "XSS Pattern Match"
		result.Category = "xss"
		result.Description = "Detected XSS pattern"
		result.Score += 20
		return result
	}
	
	if w.checkPathTraversal(fullInput) {
		result.Blocked = true
		result.RuleID = "PATH-PATTERN"
		result.RuleName = "Path Traversal Pattern Match"
		result.Category = "path_traversal"
		result.Description = "Detected path traversal pattern"
		result.Score += 20
		return result
	}
	
	if w.checkRCE(fullInput) {
		result.Blocked = true
		result.RuleID = "RCE-PATTERN"
		result.RuleName = "RCE Pattern Match"
		result.Category = "rce"
		result.Description = "Detected remote code execution pattern"
		result.Score += 20
		return result
	}
	
	// Check for bad bots if enabled
	if w.config.BlockBadBots && w.isBadBot(req.UserAgent) {
		result.Blocked = true
		result.RuleID = "BOT-001"
		result.RuleName = "Bad Bot Detection"
		result.Category = "bad_bot"
		result.Description = "Detected malicious bot or scanner"
		result.Score += 15
		return result
	}
	
	return result
}

func (w *WAFEngine) checkSQLInjection(input string) bool {
	for _, pattern := range w.sqlPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func (w *WAFEngine) checkXSS(input string) bool {
	for _, pattern := range w.xssPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func (w *WAFEngine) checkPathTraversal(input string) bool {
	for _, pattern := range w.pathPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func (w *WAFEngine) checkRCE(input string) bool {
	for _, pattern := range w.rcePatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func (w *WAFEngine) isBadBot(userAgent string) bool {
	badBots := []string{
		"sqlmap",
		"nikto",
		"nmap",
		"masscan",
		"zgrab",
		"gobuster",
		"dirbuster",
		"wpscan",
		"joomscan",
		"burpsuite",
		"acunetix",
		"nessus",
		"openvas",
		"w3af",
		"havij",
		"python-requests",
		"curl/",
		"wget/",
		"scanner",
		"harvest",
	}
	
	userAgentLower := strings.ToLower(userAgent)
	for _, bot := range badBots {
		if strings.Contains(userAgentLower, bot) {
			return true
		}
	}
	
	return false
}

// AddRule adds a custom rule to the WAF
func (w *WAFEngine) AddRule(rule config.Rule) error {
	pattern, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return err
	}
	
	w.mu.Lock()
	defer w.mu.Unlock()
	
	w.rules = append(w.rules, WAFRule{
		ID:          rule.ID,
		Name:        rule.Name,
		Pattern:     pattern,
		Action:      rule.Action,
		Description: rule.Description,
		Enabled:     rule.Enabled,
		Category:    "custom",
	})
	
	return nil
}

// RemoveRule removes a rule by ID
func (w *WAFEngine) RemoveRule(ruleID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	for i, rule := range w.rules {
		if rule.ID == ruleID {
			w.rules = append(w.rules[:i], w.rules[i+1:]...)
			return
		}
	}
}

// GetRules returns all rules
func (w *WAFEngine) GetRules() []WAFRule {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	rulesCopy := make([]WAFRule, len(w.rules))
	copy(rulesCopy, w.rules)
	return rulesCopy
}
