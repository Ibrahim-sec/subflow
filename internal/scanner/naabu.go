package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// RunNaabu performs port scanning
func RunNaabu(domains []string, ports string) ([]string, error) {
	if !CheckNaabuInstalled() {
		return nil, fmt.Errorf("naabu not installed")
	}

	if len(domains) == 0 {
		return nil, nil
	}

	// Create temp file with domains
	tmpFile, err := os.CreateTemp("", "naabu-input-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, domain := range domains {
		fmt.Fprintln(tmpFile, domain)
	}
	tmpFile.Close()

	args := []string{
		"-l", tmpFile.Name(),
		"-p", ports,
		"-silent",
	}

	cmd := exec.Command("naabu", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start naabu: %w", err)
	}

	var results []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			results = append(results, line)
		}
	}

	cmd.Wait()
	return results, nil
}

// CheckNaabuInstalled checks if naabu is available
func CheckNaabuInstalled() bool {
	_, err := exec.LookPath("naabu")
	return err == nil
}

