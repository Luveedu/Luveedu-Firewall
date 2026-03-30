package waf

import (
	"net/http"
	"regexp"
	"strings"
	"time"
)

// WAF represents the Web Application Firewall
type WAF struct {
	sqlInjectionPatterns []*regexp.Regexp
	xssPatterns          []*regexp.Regexp
	rcePatterns          []*regexp.Regexp
	lfiPatterns          []*regexp.Regexp
}

// ThreatType represents the type of detected threat
type ThreatType int

const (
	ThreatNone ThreatType = iota
	ThreatSQLi
	ThreatXSS
	ThreatRCE
	ThreatLFI
	ThreatRFI
	ThreatMaliciousUA
)

func (t ThreatType) String() string {
	switch t {
	case ThreatSQLi:
		return "SQL Injection"
	case ThreatXSS:
		return "Cross-Site Scripting (XSS)"
	case ThreatRCE:
		return "Remote Code Execution (RCE)"
	case ThreatLFI:
		return "Local File Inclusion (LFI)"
	case ThreatRFI:
		return "Remote File Inclusion (RFI)"
	case ThreatMaliciousUA:
		return "Malicious User-Agent"
	default:
		return "Unknown Threat"
	}
}

// NewWAF creates a new WAF instance with OWASP Top 10 patterns
func NewWAF() *WAF {
	return &WAF{
		sqlInjectionPatterns: compilePatterns([]string{
			`(?i)(\bunion\b.*\bselect\b)`,
			`(?i)(\bselect\b.*\bfrom\b)`,
			`(?i)(\binsert\b.*\binto\b)`,
			`(?i)(\bdelete\b.*\bfrom\b)`,
			`(?i)(\bupdate\b.*\bset\b)`,
			`(?i)(\bdrop\b.*\btable\b)`,
			`(?i)(\bexec\b.*\b\()`,
			`(?i)(\bexecute\b.*\b\()`,
			`(?i)(--\s*$)`,
			`(?i)(;\s*--)`,
			`(?i)(\bor\b\s+\d+\s*=\s*\d+)`,
			`(?i)(\band\b\s+\d+\s*=\s*\d+)`,
			`(?i)('|\")(\s*or\s*|\s*and\s*)('|\")`,
			`(?i)(benchmark\s*\()`,
			`(?i)(sleep\s*\()`,
			`(?i)(waitfor\s+delay)`,
		}),
		xssPatterns: compilePatterns([]string{
			`(?i)(<script[^>]*>)`,
			`(?i)(</script>)`,
			`(?i)(javascript\s*:`,
			`(?i)(on(load|error|click|mouse|focus|blur)\s*=)`,
			`(?i)(<iframe[^>]*>)`,
			`(?i)(<object[^>]*>)`,
			`(?i)(<embed[^>]*>)`,
			`(?i)(<svg[^>]*onload)`,
			`(?i)(expression\s*\()`,
			`(?i)(url\s*\(\s*['\"]?javascript)`,
		}),
		rcePatterns: compilePatterns([]string{
			`(?i)(\bcat\b\s+/)`,
			`(?i)(\bls\b\s+-)`,
			`(?i)(\bwget\b\s+)`,
			`(?i)(\bcurl\b\s+)`,
			`(?i)(\bnc\b\s+-)`,
			`(?i)(\bnetcat\b\s+)`,
			`(?i)(\bbash\s+-i)`,
			`(?i)(\bperl\s+-e)`,
			`(?i)(\bpython\s+-c)`,
			`(?i)(\bruby\s+-e)`,
			`(?i)(\bphp\s+-r)`,
			`(?i)(\beval\s*\()`,
			`(?i)(\bsystem\s*\()`,
			`(?i)(\bexec\s*\()`,
			`(?i)(\bpassthru\s*\()`,
			`(?i)(\bshell_exec\s*\()`,
			`(?i)(\bpopen\s*\()`,
			`(?i)(\bproc_open\s*\()`,
			`(?i)(\|.*\b(sh|bash|zsh|ksh)\b)`,
			`(?i)(;\s*(sh|bash|zsh|ksh)\b)`,
			`(?i)(\$\([^\)]+\))`,
			`(?i)(\x60[^\x60]+\x60)`,
		}),
		lfiPatterns: compilePatterns([]string{
			`(?i)(\.\./)`,
			`(?i)(\.\.\\)`,
			`(?i)(/etc/passwd)`,
			`(?i)(/etc/shadow)`,
			`(?i)(/etc/hosts)`,
			`(?i)(/proc/self/)`,
			`(?i)(/var/log/)`,
			`(?i)(file://)`,
			`(?i)(expect://)`,
			`(?i)(data://)`,
			`(?i)(php://filter)`,
			`(?i)(php://input)`,
			`(?i)(zip://)`,
			`(?i)(phar://)`,
		}),
	}
}

func compilePatterns(patterns []string) []*regexp.Regexp {
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

// CheckRequest inspects an HTTP request for threats
func (w *WAF) CheckRequest(r *http.Request) (ThreatType, string) {
	// Check URL path
	if threat, match := w.checkString(r.URL.Path); threat != ThreatNone {
		return threat, match
	}

	// Check query parameters
	if threat, match := w.checkString(r.URL.RawQuery); threat != ThreatNone {
		return threat, match
	}

	// Check headers
	for key, values := range r.Header {
		for _, value := range values {
			if threat, match := w.checkString(value); threat != ThreatNone {
				// Special check for User-Agent
				if strings.ToLower(key) == "user-agent" && isMaliciousUA(value) {
					return ThreatMaliciousUA, value
				}
				return threat, match
			}
		}
	}

	// Check cookies
	for _, cookie := range r.Cookies() {
		if threat, match := w.checkString(cookie.Value); threat != ThreatNone {
			return threat, match
		}
	}

	return ThreatNone, ""
}

// checkString checks a single string against all pattern sets
func (w *WAF) checkString(s string) (ThreatType, string) {
	// SQL Injection
	for _, re := range w.sqlInjectionPatterns {
		if match := re.FindString(s); match != "" {
			return ThreatSQLi, match
		}
	}

	// XSS
	for _, re := range w.xssPatterns {
		if match := re.FindString(s); match != "" {
			return ThreatXSS, match
		}
	}

	// RCE
	for _, re := range w.rcePatterns {
		if match := re.FindString(s); match != "" {
			return ThreatRCE, match
		}
	}

	// LFI/RFI
	for _, re := range w.lfiPatterns {
		if match := re.FindString(s); match != "" {
			return ThreatLFI, match
		}
	}

	return ThreatNone, ""
}

// isMaliciousUA checks if User-Agent is from known malicious bots/scanners
func isMaliciousUA(ua string) bool {
	maliciousUAs := []string{
		"sqlmap",
		"nikto",
		"nmap",
		"masscan",
		"nessus",
		"openvas",
		"burp",
		"acunetix",
		"w3af",
		"arachni",
		"havij",
		"pangolin",
		"dirbuster",
		"gobuster",
		"wfuzz",
		"hydra",
		"medusa",
		"metasploit",
		"curl/",
		"wget/",
		"python-requests",
		"go-http-client",
	}

	uaLower := strings.ToLower(ua)
	for _, mal := range maliciousUAs {
		if strings.Contains(uaLower, mal) {
			return true
		}
	}
	return false
}

// SanitizeInput removes potentially dangerous characters from input
func (w *WAF) SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Encode HTML special characters
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#x27;")
	input = strings.ReplaceAll(input, "/", "&#x2F;")
	
	// Remove backslashes
	input = strings.ReplaceAll(input, "\\", "")
	
	return input
}

// LogFormat formats a threat detection for logging
func LogFormat(ip string, threat ThreatType, match string, path string) string {
	return "[" + time.Now().Format(time.RFC3339) + "] THREAT DETECTED | IP: " + ip + 
		" | Type: " + threat.String() + 
		" | Match: " + match + 
		" | Path: " + path
}
