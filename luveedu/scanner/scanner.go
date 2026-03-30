package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ScanResult represents the result of a malware scan
type ScanResult struct {
	FilePath     string
	ThreatName   string
	ScanTime     time.Time
	IsInfected   bool
	Quarantined  bool
}

// Scanner handles malware scanning with ClamAV and rkhunter
type Scanner struct {
	quarantineDir string
}

// NewScanner creates a new malware scanner
func NewScanner(quarantineDir string) *Scanner {
	return &Scanner{
		quarantineDir: quarantineDir,
	}
}

// ScanFile scans a single file with ClamAV
func (s *Scanner) ScanFile(filePath string) (*ScanResult, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", filePath)
	}

	// Run clamscan
	cmd := exec.Command("clamscan", "--no-summary", filePath)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// clamscan returns 1 when threats found, which is expected
			if exitErr.ExitCode() == 1 {
				// Parse output to get threat name
				lines := strings.Split(string(output), "\n")
				for _, line := range lines {
					if strings.Contains(line, "FOUND") {
						parts := strings.Split(line, ":")
						if len(parts) >= 2 {
							threatName := strings.TrimSpace(strings.TrimSuffix(parts[1], "FOUND"))
							return &ScanResult{
								FilePath:   filePath,
								ThreatName: threatName,
								ScanTime:   time.Now(),
								IsInfected: true,
							}, nil
						}
					}
				}
			}
		}
		// No threats found
		return &ScanResult{
			FilePath:   filePath,
			ScanTime:   time.Now(),
			IsInfected: false,
		}, nil
	}

	// Clean file
	return &ScanResult{
		FilePath:   filePath,
		ScanTime:   time.Now(),
		IsInfected: false,
	}, nil
}

// ScanDirectory recursively scans a directory for malware
func (s *Scanner) ScanDirectory(dirPath string) ([]*ScanResult, error) {
	var results []*ScanResult

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip very large files (>100MB)
		if info.Size() > 100*1024*1024 {
			return nil
		}

		result, err := s.ScanFile(path)
		if err != nil {
			return err
		}

		results = append(results, result)
		return nil
	})

	return results, err
}

// Quarantine moves an infected file to quarantine
func (s *Scanner) Quarantine(filePath string) error {
	// Create quarantine directory if it doesn't exist
	if err := os.MkdirAll(s.quarantineDir, 0750); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %v", err)
	}

	// Generate unique filename
	baseName := filepath.Base(filePath)
	timestamp := time.Now().Format("20060102_150405")
	quarantineName := fmt.Sprintf("%s_%s", timestamp, baseName)
	quarantinePath := filepath.Join(s.quarantineDir, quarantineName)

	// Move file to quarantine
	if err := os.Rename(filePath, quarantinePath); err != nil {
		// Try copy + delete if rename fails
		srcData, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file for quarantine: %v", err)
		}

		if err := os.WriteFile(quarantinePath, srcData, 0640); err != nil {
			return fmt.Errorf("failed to write quarantined file: %v", err)
		}

		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("failed to remove original file: %v", err)
		}
	}

	return nil
}

// ScanAndQuarantine scans a file and quarantines if infected
func (s *Scanner) ScanAndQuarantine(filePath string) (*ScanResult, error) {
	result, err := s.ScanFile(filePath)
	if err != nil {
		return nil, err
	}

	if result.IsInfected {
		if err := s.Quarantine(filePath); err != nil {
			return result, fmt.Errorf("failed to quarantine: %v", err)
		}
		result.Quarantined = true
	}

	return result, nil
}

// CheckRootkit runs rkhunter to check for rootkits
func CheckRootkit() ([]string, error) {
	// Check if rkhunter is installed
	if _, err := exec.LookPath("rkhunter"); err != nil {
		return nil, fmt.Errorf("rkhunter not installed")
	}

	// Run rkhunter check
	cmd := exec.Command("rkhunter", "--check", "--skip-keypress")
	output, err := cmd.CombinedOutput()
	
	var warnings []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Warning:") || strings.Contains(line, "[!]") {
			warnings = append(warnings, line)
		}
	}

	return warnings, err
}

// UpdateSignatures updates ClamAV virus definitions
func UpdateSignatures() error {
	// Check if freshclam is installed
	if _, err := exec.LookPath("freshclam"); err != nil {
		return fmt.Errorf("freshclam not installed")
	}

	cmd := exec.Command("freshclam", "--quiet")
	return cmd.Run()
}

// GetScanSummary generates a summary of scan results
func GetScanSummary(results []*ScanResult) string {
	total := len(results)
	infected := 0
	quarantined := 0

	for _, r := range results {
		if r.IsInfected {
			infected++
			if r.Quarantined {
				quarantined++
			}
		}
	}

	summary := fmt.Sprintf("Scan Summary:\n")
	summary += fmt.Sprintf("  Total files scanned: %d\n", total)
	summary += fmt.Sprintf("  Infected files: %d\n", infected)
	summary += fmt.Sprintf("  Quarantined files: %d\n", quarantined)
	summary += fmt.Sprintf("  Clean files: %d\n", total-infected)

	if infected > 0 {
		summary += "\nInfected files:\n"
		for _, r := range results {
			if r.IsInfected {
				status := "NOT quarantined"
				if r.Quarantined {
					status = "quarantined"
				}
				summary += fmt.Sprintf("  - %s [%s] (%s)\n", r.FilePath, r.ThreatName, status)
			}
		}
	}

	return summary
}
