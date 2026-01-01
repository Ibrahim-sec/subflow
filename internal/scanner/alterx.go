package scanner

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// AlterxPattern represents an alterx permutation pattern
type AlterxPattern struct {
	Pattern  string
	WordList string
}

// DefaultAlterxPatterns returns the default alterx patterns
func DefaultAlterxPatterns() []AlterxPattern {
	return []AlterxPattern{
		{Pattern: "{{word}}.{{suffix}}", WordList: "subdomains-10000.txt"},
		{Pattern: "{{sub}}.{{word}}.{{suffix}}", WordList: "subdomains-10000.txt"},
		{Pattern: "{{word}}.{{sub}}.{{suffix}}", WordList: "subdomains-10000.txt"},
		{Pattern: "{{sub}}-{{word}}.{{suffix}}", WordList: "subdomains-10000.txt"},
		{Pattern: "{{word}}-{{sub}}.{{suffix}}", WordList: "subdomains-10000.txt"},
		{Pattern: "{{sub}}{{word}}.{{suffix}}", WordList: "subdomains-10000.txt"},
		{Pattern: "{{word}}{{sub}}.{{suffix}}", WordList: "subdomains-10000.txt"},
	}
}

// RunAlterx generates subdomain permutations using alterx
func RunAlterx(subdomains []string, pattern AlterxPattern) ([]string, error) {
	if !CheckAlterxInstalled() {
		return nil, fmt.Errorf("alterx not installed")
	}

	if len(subdomains) == 0 {
		return nil, nil
	}

	args := []string{
		"-en", // enrich
		"-p", pattern.Pattern,
		"-silent",
	}

	if pattern.WordList != "" {
		args = append(args, "-pp", "word="+pattern.WordList)
	}

	cmd := exec.Command("alterx", args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start alterx: %w", err)
	}

	go func() {
		defer stdin.Close()
		for _, sub := range subdomains {
			fmt.Fprintln(stdin, sub)
		}
	}()

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

// RunAlterxParallel runs multiple alterx patterns in parallel
func RunAlterxParallel(subdomains []string, patterns []AlterxPattern) []string {
	if len(subdomains) == 0 || len(patterns) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	resultChan := make(chan []string, len(patterns))

	for _, pattern := range patterns {
		wg.Add(1)
		go func(p AlterxPattern) {
			defer wg.Done()
			results, err := RunAlterx(subdomains, p)
			if err != nil {
				return
			}
			resultChan <- results
		}(pattern)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	seen := make(map[string]bool)
	var allResults []string

	for _, sub := range subdomains {
		if !seen[sub] {
			seen[sub] = true
			allResults = append(allResults, sub)
		}
	}

	for results := range resultChan {
		for _, r := range results {
			if !seen[r] {
				seen[r] = true
				allResults = append(allResults, r)
			}
		}
	}

	return allResults
}

// RunDnsx validates domains using DNS resolution
func RunDnsx(domains []string) ([]string, error) {
	if !CheckDnsxInstalled() {
		return nil, fmt.Errorf("dnsx not installed")
	}

	if len(domains) == 0 {
		return nil, nil
	}

	args := []string{
		"-silent",
		"-resp",
	}

	cmd := exec.Command("dnsx", args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start dnsx: %w", err)
	}

	go func() {
		defer stdin.Close()
		for _, domain := range domains {
			fmt.Fprintln(stdin, domain)
		}
	}()

	var resolved []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				resolved = append(resolved, parts[0])
			}
		}
	}

	cmd.Wait()
	return resolved, nil
}

// CheckAlterxInstalled checks if alterx is available
func CheckAlterxInstalled() bool {
	_, err := exec.LookPath("alterx")
	return err == nil
}

// CheckDnsxInstalled checks if dnsx is available
func CheckDnsxInstalled() bool {
	_, err := exec.LookPath("dnsx")
	return err == nil
}

