package discovery

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// RunSubfinder runs subfinder for passive subdomain enumeration
func RunSubfinder(domain string) ([]string, error) {
	if !CheckToolInstalled("subfinder") {
		return nil, fmt.Errorf("subfinder not installed")
	}

	args := []string{
		"-d", domain,
		"-silent",
		"-all",
	}

	cmd := exec.Command("subfinder", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start subfinder: %w", err)
	}

	var subdomains []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}

	cmd.Wait()
	return subdomains, nil
}

// CheckToolInstalled checks if a tool is available in PATH
func CheckToolInstalled(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// DeduplicateStrings removes duplicates from a string slice
func DeduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// FilterNumericSubdomains removes subdomains that start with numbers
func FilterNumericSubdomains(domains []string) []string {
	var filtered []string
	for _, d := range domains {
		if len(d) > 0 && d[0] >= '0' && d[0] <= '9' {
			continue
		}
		filtered = append(filtered, d)
	}
	return filtered
}

