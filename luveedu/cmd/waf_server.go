package main

import (
	"fmt"
	"net/http"
	"time"

	"luveedu/config"
	"luveedu/engine"
	"luveedu/waf"
)

// startWAFServer starts an HTTP server that acts as a reverse proxy with WAF protection
func startWAFServer(cfg *config.Config, wafEngine *waf.WAF, blocker *engine.Blocker) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		
		// Get client IP
		clientIP := getClientIP(r)
		
		// Check if IP is blocked
		blockedIPs := blocker.GetBlockedIPs()
		for _, ip := range blockedIPs {
			if ip == clientIP {
				http.Error(w, "Access Denied - Your IP has been blocked", http.StatusForbidden)
				return
			}
		}
		
		// Run WAF checks
		threat, match := wafEngine.CheckRequest(r)
		if threat != waf.ThreatNone {
			// Log the threat
			logThreat(clientIP, threat, match, r.URL.Path)
			
			// Block the IP for repeated attacks
			if shouldBlock(threat) {
				blocker.BlockIP(clientIP, cfg.BlockDuration)
				http.Error(w, fmt.Sprintf("Blocked: %s detected", threat.String()), http.StatusForbidden)
				return
			}
			
			http.Error(w, fmt.Sprintf("Request blocked: %s", threat.String()), http.StatusBadRequest)
			return
		}
		
		// Request is clean - in production, this would proxy to backend
		// For now, just return success
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Request processed successfully in %v", time.Since(startTime))
	})
	
	addr := fmt.Sprintf(":%d", cfg.ListenPort)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Printf("WAF server error: %v\n", err)
	}
}

// getClientIP extracts the real client IP from request headers
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the chain
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	
	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	for i := 0; i < len(ip); i++ {
		if ip[i] == ':' {
			return ip[:i]
		}
	}
	return ip
}

// shouldBlock determines if a threat type warrants IP blocking
func shouldBlock(threat waf.ThreatType) bool {
	switch threat {
	case waf.ThreatSQLi, waf.ThreatRCE, waf.ThreatLFI, waf.ThreatRFI:
		return true
	case waf.ThreatMaliciousUA:
		return true
	default:
		return false
	}
}

// logThreat logs detected threats (in production, send to syslog or SIEM)
func logThreat(ip string, threat waf.ThreatType, match string, path string) {
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("[%s] THREAT | IP: %s | Type: %s | Match: %s | Path: %s\n",
		timestamp, ip, threat.String(), match, path)
	
	// In production, write to /var/log/luveedu/threats.log
	fmt.Print(logEntry)
}
