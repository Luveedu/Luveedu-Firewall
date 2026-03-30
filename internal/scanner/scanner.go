package scanner

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Luveedu/Luveedu-Firewall/internal/config"
)

// ScanResult holds the result of a malware scan
type ScanResult struct {
	Path       string    `json:"path"`
	ThreatName string    `json:"threat_name,omitempty"`
	Status     string    `json:"status"` // clean, infected, error
	ScannedAt  time.Time `json:"scanned_at"`
}

// ScanPath scans a path for malware using ClamAV and rkhunter
func ScanPath(path string, cfg *config.Config) error {
	fmt.Printf("Starting malware scan of: %s\n", path)
	fmt.Println(strings.Repeat("=", 60))

	var results []ScanResult

	// Check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", path)
	}

	// Run ClamAV scan
	if cfg.Scanner.Enabled {
		fmt.Println("\n[1/2] Running ClamAV scan...")
		clamResults, err := runClamAVScan(path, cfg)
		if err != nil {
			fmt.Printf("ClamAV scan error: %v\n", err)
		} else {
			results = append(results, clamResults...)
		}
	} else {
		fmt.Println("ClamAV scanning is disabled in configuration")
	}

	// Run rkhunter if enabled
	if cfg.Scanner.RKHunter {
		fmt.Println("\n[2/2] Running rkhunter rootkit scan...")
		rkhResults, err := runRKHunter(path, cfg)
		if err != nil {
			fmt.Printf("rkhunter scan error: %v\n", err)
		} else {
			results = append(results, rkhResults...)
		}
	} else {
		fmt.Println("rkhunter scanning is disabled in configuration")
	}

	// Print summary
	printScanSummary(results)

	// Check for infections
	infected := 0
	for _, r := range results {
		if r.Status == "infected" {
			infected++
		}
	}

	if infected > 0 {
		fmt.Printf("\n⚠ WARNING: %d threat(s) detected!\n", infected)
		if cfg.Scanner.AutoClean {
			fmt.Println("Auto-cleaning enabled - moving infected files to quarantine...")
			quarantineInfected(results, cfg)
		}
		return fmt.Errorf("%d malware threats detected", infected)
	}

	fmt.Println("\n✓ No threats detected. System is clean.")
	return nil
}

// runClamAVScan runs ClamAV scan on the specified path
func runClamAVScan(path string, cfg *config.Config) ([]ScanResult, error) {
	var results []ScanResult

	// Check if clamd is running
	if !checkClamDRunning(cfg) {
		log.Printf("ClamAV daemon not running, falling back to clamscan")
		return runClamScan(path, cfg)
	}

	// Use clamdscan for faster scanning
	cmd := exec.Command("clamdscan", "--no-summary", path)
	output, err := cmd.CombinedOutput()
	
	if err != nil && !strings.Contains(string(output), "FOUND") {
		return nil, fmt.Errorf("clamdscan failed: %w", err)
	}

	// Parse output
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ": ") && strings.Contains(line, "FOUND") {
			parts := strings.Split(line, ": ")
			if len(parts) >= 2 {
				filePath := strings.TrimSpace(parts[0])
				threatName := strings.TrimSpace(parts[1])
				
				results = append(results, ScanResult{
					Path:       filePath,
					ThreatName: threatName,
					Status:     "infected",
					ScannedAt:  time.Now(),
				})
			}
		} else if strings.Contains(line, ": OK") {
			filePath := strings.Split(line, ": ")[0]
			results = append(results, ScanResult{
				Path:      filePath,
				Status:    "clean",
				ScannedAt: time.Now(),
			})
		}
	}

	return results, nil
}

// runClamScan runs clamscan (slower but doesn't require daemon)
func runClamScan(path string, cfg *config.Config) ([]ScanResult, error) {
	var results []ScanResult

	args := []string{"--no-summary", "-r", path}
	cmd := exec.Command("clamscan", args...)
	output, _ := cmd.CombinedOutput()

	// Parse output for infected files
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "FOUND") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				filePath := parts[0]
				threatName := strings.TrimSuffix(parts[len(parts)-1], "FOUND")
				
				results = append(results, ScanResult{
					Path:       filePath,
					ThreatName: threatName,
					Status:     "infected",
					ScannedAt:  time.Now(),
				})
			}
		}
	}

	// Also count clean files from summary
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "OK") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				results = append(results, ScanResult{
					Path:      parts[0],
					Status:    "clean",
					ScannedAt: time.Now(),
				})
			}
		}
	}

	return results, nil
}

// runRKHunter runs rkhunter rootkit detection
func runRKHunter(path string, cfg *config.Config) ([]ScanResult, error) {
	var results []ScanResult

	// Update rkhunter database first
	updateCmd := exec.Command("rkhunter", "--update")
	updateCmd.Run()

	// Run rkhunter check
	cmd := exec.Command("rkhunter", "--check", "--sk", "--report-warnings-only")
	output, err := cmd.CombinedOutput()

	// Parse output for warnings
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "[ Warning ]") || strings.Contains(line, "[ Rootkit ]") {
			results = append(results, ScanResult{
				Path:       "system",
				ThreatName: line,
				Status:     "infected",
				ScannedAt:  time.Now(),
			})
		}
	}

	// If no specific warnings but command had issues, still report
	if len(results) == 0 && err != nil {
		results = append(results, ScanResult{
			Path:       "system",
			ThreatName: string(output),
			Status:     "error",
			ScannedAt:  time.Now(),
		})
	} else if len(results) == 0 {
		results = append(results, ScanResult{
			Path:      "system",
			Status:    "clean",
			ScannedAt: time.Now(),
		})
	}

	return results, nil
}

// checkClamDRunning checks if clamd daemon is running
func checkClamDRunning(cfg *config.Config) bool {
	cmd := exec.Command("pgrep", "-x", "clamd")
	return cmd.Run() == nil
}

// printScanSummary prints a summary of scan results
func printScanSummary(results []ScanResult) {
	clean := 0
	infected := 0
	errors := 0

	for _, r := range results {
		switch r.Status {
		case "clean":
			clean++
		case "infected":
			infected++
		case "error":
			errors++
		}
	}

	fmt.Println("\n" + strings.Repeat("-", 60))
	fmt.Println("SCAN SUMMARY")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Total files scanned: %d\n", len(results))
	fmt.Printf("Clean files:         %d\n", clean)
	fmt.Printf("Infected files:      %d\n", infected)
	fmt.Printf("Errors:              %d\n", errors)
	fmt.Println(strings.Repeat("-", 60))

	// Show infected files
	if infected > 0 {
		fmt.Println("\nINFECTED FILES:")
		for _, r := range results {
			if r.Status == "infected" {
				fmt.Printf("  ✗ %s\n", r.Path)
				fmt.Printf("    Threat: %s\n", r.ThreatName)
			}
		}
	}
}

// quarantineInfected moves infected files to quarantine directory
func quarantineInfected(results []ScanResult, cfg *config.Config) {
	quarantineDir := cfg.Scanner.QuarantineDir
	
	if err := os.MkdirAll(quarantineDir, 0755); err != nil {
		log.Printf("Failed to create quarantine directory: %v", err)
		return
	}

	for _, r := range results {
		if r.Status == "infected" {
			filename := filepath.Base(r.Path)
			timestamp := time.Now().Format("20060102_150405")
			quarantinePath := filepath.Join(quarantineDir, fmt.Sprintf("%s_%s", timestamp, filename))

			// Move file to quarantine
			if err := os.Rename(r.Path, quarantinePath); err != nil {
				// If rename fails (cross-device), try copy+delete
				input, err := os.ReadFile(r.Path)
				if err != nil {
					log.Printf("Failed to read infected file %s: %v", r.Path, err)
					continue
				}

				if err := os.WriteFile(quarantinePath, input, 0600); err != nil {
					log.Printf("Failed to write quarantined file %s: %v", quarantinePath, err)
					continue
				}

				os.Remove(r.Path)
			}

			log.Printf("Quarantined: %s -> %s", r.Path, quarantinePath)
		}
	}
}

// ScheduleScan schedules regular scans (called from main engine)
func ScheduleScan(cfg *config.Config) {
	if !cfg.Scanner.Enabled {
		return
	}

	ticker := time.NewTicker(24 * time.Hour) // Daily scan
	defer ticker.Stop()

	for range ticker.C {
		for _, scanPath := range cfg.Scanner.ScanPaths {
			log.Printf("Starting scheduled scan of: %s", scanPath)
			if err := ScanPath(scanPath, cfg); err != nil {
				log.Printf("Scheduled scan completed with issues: %v", err)
			}
		}
	}
}
