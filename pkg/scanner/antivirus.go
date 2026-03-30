package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MalwareScanner handles malware scanning with ClamAV and rkhunter
type MalwareScanner struct {
	config       *ScannerConfig
	quarantineDir string
	mu           sync.Mutex
	stats        ScanStats
}

// ScannerConfig holds scanner configuration
type ScannerConfig struct {
	Enabled        bool
	QuarantineDir  string
	MaxFileSize    int64
	FileExtensions []string
	ExcludePaths   []string
	ScanSchedule   string
}

// ScanStats holds scanning statistics
type ScanStats struct {
	TotalScans     int
	FilesScanned   int
	ThreatsFound   int
	LastScanTime   time.Time
	LastScanResult string
}

// ScanResult represents the result of a file scan
type ScanResult struct {
	FilePath      string
	IsInfected    bool
	ThreatName    string
	ScanTime      time.Time
	FileSize      int64
	Checksum      string
	Action        string // cleaned, quarantined, deleted, skipped
}

// NewMalwareScanner creates a new malware scanner
func NewMalwareScanner(cfg *ScannerConfig) *MalwareScanner {
	return &MalwareScanner{
		config:       cfg,
		quarantineDir: cfg.QuarantineDir,
		stats:        ScanStats{},
	}
}

// ScanFile scans a single file for malware
func (ms *MalwareScanner) ScanFile(filePath string) (*ScanResult, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	
	result := &ScanResult{
		FilePath: filePath,
		ScanTime: time.Now(),
	}
	
	// Check if file should be excluded
	if ms.shouldExclude(filePath) {
		result.Action = "skipped"
		return result, nil
	}
	
	// Check file size
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	
	if fileInfo.Size() > ms.config.MaxFileSize {
		result.Action = "skipped"
		return result, fmt.Errorf("file too large: %d bytes", fileInfo.Size())
	}
	
	result.FileSize = fileInfo.Size()
	
	// Calculate checksum
	checksum, err := ms.calculateChecksum(filePath)
	if err == nil {
		result.Checksum = checksum
	}
	
	// Scan with ClamAV
	clamResult, err := ms.scanWithClamAV(filePath)
	if err != nil {
		return result, err
	}
	
	if clamResult.IsInfected {
		result.IsInfected = true
		result.ThreatName = clamResult.ThreatName
		ms.stats.ThreatsFound++
		
		// Quarantine the file
		if err := ms.quarantineFile(filePath); err != nil {
			result.Action = "deleted"
			os.Remove(filePath)
		} else {
			result.Action = "quarantined"
		}
	} else {
		result.Action = "cleaned"
	}
	
	ms.stats.FilesScanned++
	return result, nil
}

// ScanDirectory scans a directory recursively
func (ms *MalwareScanner) ScanDirectory(dirPath string) ([]*ScanResult, error) {
	var results []*ScanResult
	var wg sync.WaitGroup
	resultChan := make(chan *ScanResult, 100)
	errorChan := make(chan error, 10)
	
	// Ensure quarantine directory exists
	if err := os.MkdirAll(ms.quarantineDir, 0750); err != nil {
		return nil, err
	}
	
	// Walk directory
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return nil
		}
		
		// Check file extension
		if !ms.hasValidExtension(path) {
			return nil
		}
		
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			result, err := ms.ScanFile(filePath)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- result
		}(path)
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	// Wait for all scans to complete
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()
	
	// Collect results
	for result := range resultChan {
		results = append(results, result)
	}
	
	// Collect errors
	for err := range errorChan {
		fmt.Printf("Scan error: %v\n", err)
	}
	
	ms.stats.TotalScans++
	ms.stats.LastScanTime = time.Now()
	
	return results, nil
}

// scanWithClamAV scans a file using ClamAV
func (ms *MalwareScanner) scanWithClamAV(filePath string) (*ScanResult, error) {
	// Try clamscan first
	cmd := exec.Command("clamscan", "--no-summary", filePath)
	var out bytes.Buffer
	cmd.Stdout = &out
	
	err := cmd.Run()
	if err == nil {
		// File is clean
		return &ScanResult{IsInfected: false}, nil
	}
	
	// Check if file is infected
	output := out.String()
	if strings.Contains(output, "FOUND") {
		parts := strings.Split(output, ":")
		threatName := ""
		if len(parts) > 1 {
			threatName = strings.TrimSpace(strings.Split(parts[1], "FOUND")[0])
		}
		
		return &ScanResult{
			IsInfected: true,
			ThreatName: threatName,
		}, nil
	}
	
	// If clamscan not available, try clamdscan
	cmd = exec.Command("clamdscan", "--no-summary", filePath)
	out.Reset()
	cmd.Stdout = &out
	
	err = cmd.Run()
	if err == nil {
		return &ScanResult{IsInfected: false}, nil
	}
	
	output = out.String()
	if strings.Contains(output, "FOUND") {
		parts := strings.Split(output, ":")
		threatName := ""
		if len(parts) > 1 {
			threatName = strings.TrimSpace(strings.Split(parts[1], "FOUND")[0])
		}
		
		return &ScanResult{
			IsInfected: true,
			ThreatName: threatName,
		}, nil
	}
	
	return &ScanResult{IsInfected: false}, nil
}

// quarantineFile moves an infected file to quarantine
func (ms *MalwareScanner) quarantineFile(filePath string) error {
	// Create unique quarantine name
	baseName := filepath.Base(filePath)
	timestamp := time.Now().Format("20060102_150405")
	quarantineName := fmt.Sprintf("%s_%s", timestamp, baseName)
	quarantinePath := filepath.Join(ms.quarantineDir, quarantineName)
	
	// Move file to quarantine
	if err := os.Rename(filePath, quarantinePath); err != nil {
		// If rename fails, try copy and delete
		input, err := ioutil.ReadFile(filePath)
		if err != nil {
			return err
		}
		
		if err := ioutil.WriteFile(quarantinePath, input, 0600); err != nil {
			return err
		}
		
		return os.Remove(filePath)
	}
	
	// Save metadata
	metadata := map[string]interface{}{
		"original_path": filePath,
		"quarantine_path": quarantinePath,
		"quarantine_time": time.Now().Format("2006-01-02T15:04:05Z07:00"),
		"reason": "malware_detected",
	}
	
	metadataPath := quarantinePath + ".json"
	metadataJSON, _ := json.MarshalIndent(metadata, "", "  ")
	return ioutil.WriteFile(metadataPath, metadataJSON, 0600)
}

// RunRootkitScan runs rkhunter to detect rootkits
func (ms *MalwareScanner) RunRootkitScan() (*ScanResult, error) {
	cmd := exec.Command("rkhunter", "--check", "--skip-keypress", "--report-warnings-only")
	var out bytes.Buffer
	cmd.Stdout = &out
	
	err := cmd.Run()
	
	result := &ScanResult{
		FilePath: "system",
		ScanTime: time.Now(),
	}
	
	if err == nil {
		result.IsInfected = false
		result.Action = "cleaned"
		return result, nil
	}
	
	// Parse output for warnings
	output := out.String()
	if strings.Contains(output, "Warning") || strings.Contains(output, "INFECTED") {
		result.IsInfected = true
		result.ThreatName = "Rootkit detected"
		result.Action = "alert"
		ms.stats.ThreatsFound++
	}
	
	return result, nil
}

// shouldExclude checks if a path should be excluded from scanning
func (ms *MalwareScanner) shouldExclude(filePath string) bool {
	for _, excludePath := range ms.config.ExcludePaths {
		if strings.HasPrefix(filePath, excludePath) {
			return true
		}
	}
	return false
}

// hasValidExtension checks if a file has a valid extension for scanning
func (ms *MalwareScanner) hasValidExtension(filePath string) bool {
	if len(ms.config.FileExtensions) == 0 {
		return true // Scan all files if no extensions specified
	}
	
	ext := strings.ToLower(filepath.Ext(filePath))
	for _, validExt := range ms.config.FileExtensions {
		if ext == validExt {
			return true
		}
	}
	return false
}

// calculateChecksum calculates MD5 checksum of a file
func (ms *MalwareScanner) calculateChecksum(filePath string) (string, error) {
	cmd := exec.Command("md5sum", filePath)
	var out bytes.Buffer
	cmd.Stdout = &out
	
	if err := cmd.Run(); err != nil {
		return "", err
	}
	
	parts := strings.Fields(out.String())
	if len(parts) > 0 {
		return parts[0], nil
	}
	
	return "", fmt.Errorf("failed to calculate checksum")
}

// GetStats returns scanner statistics
func (ms *MalwareScanner) GetStats() ScanStats {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return ms.stats
}

// UpdateVirusDefinitions updates ClamAV virus definitions
func (ms *MalwareScanner) UpdateVirusDefinitions() error {
	cmd := exec.Command("freshclam")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update virus definitions: %v", err)
	}
	
	return nil
}

// GenerateReport generates a scan report
func (ms *MalwareScanner) GenerateReport(results []*ScanResult) string {
	var report strings.Builder
	
	report.WriteString("=== Luveedu Antivirus Scan Report ===\n\n")
	report.WriteString(fmt.Sprintf("Scan Time: %s\n", time.Now().Format(time.RFC3339)))
	report.WriteString(fmt.Sprintf("Total Files Scanned: %d\n", ms.stats.FilesScanned))
	report.WriteString(fmt.Sprintf("Threats Found: %d\n", ms.stats.ThreatsFound))
	report.WriteString("\n")
	
	infectedCount := 0
	for _, result := range results {
		if result.IsInfected {
			infectedCount++
			report.WriteString(fmt.Sprintf("[INFECTED] %s\n", result.FilePath))
			report.WriteString(fmt.Sprintf("  Threat: %s\n", result.ThreatName))
			report.WriteString(fmt.Sprintf("  Action: %s\n", result.Action))
			report.WriteString("\n")
		}
	}
	
	if infectedCount == 0 {
		report.WriteString("No threats detected.\n")
	}
	
	return report.String()
}

