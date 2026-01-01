package scanner

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// WildcardInfo contains wildcard detection results
type WildcardInfo struct {
	IsWildcard     bool
	WildcardIPs    []string
	BaselineStatus int
	BaselineCL     int64
	BaselineWords  int
}

var (
	wildcardCache   = make(map[string]*WildcardInfo)
	wildcardCacheMu sync.RWMutex
)

// generateRandomSubdomain creates a random subdomain that shouldn't exist
func generateRandomSubdomain(target string) string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	random := hex.EncodeToString(bytes)
	return fmt.Sprintf("%s.%s", random, target)
}

// DetectWildcardDNS checks if a domain has wildcard DNS configured
func DetectWildcardDNS(target string) *WildcardInfo {
	wildcardCacheMu.RLock()
	if info, exists := wildcardCache[target]; exists {
		wildcardCacheMu.RUnlock()
		return info
	}
	wildcardCacheMu.RUnlock()

	info := &WildcardInfo{}

	var resolvedIPs []string
	checksNeeded := 3
	checksResolved := 0

	for i := 0; i < checksNeeded; i++ {
		randomSub := generateRandomSubdomain(target)
		ips, err := net.LookupHost(randomSub)
		if err == nil && len(ips) > 0 {
			checksResolved++
			resolvedIPs = append(resolvedIPs, ips...)
		}
	}

	if checksResolved >= 2 {
		info.IsWildcard = true
		info.WildcardIPs = deduplicateStrings(resolvedIPs)
	}

	wildcardCacheMu.Lock()
	wildcardCache[target] = info
	wildcardCacheMu.Unlock()

	return info
}

// DetectWildcardHTTP checks for wildcard HTTP responses
func DetectWildcardHTTP(target string) *WildcardInfo {
	wildcardCacheMu.RLock()
	info, exists := wildcardCache[target]
	wildcardCacheMu.RUnlock()

	if !exists {
		info = &WildcardInfo{}
	}

	if info.BaselineStatus > 0 {
		return info
	}

	randomSub := generateRandomSubdomain(target)
	result := ProbeWithHttpx(randomSub)

	if result.StatusCode > 0 {
		info.IsWildcard = true
		info.BaselineStatus = result.StatusCode
		info.BaselineCL = result.ContentLength
		info.BaselineWords = result.Words
	}

	wildcardCacheMu.Lock()
	wildcardCache[target] = info
	wildcardCacheMu.Unlock()

	return info
}

// FilterWildcardHTTPResults filters probe results that match wildcard baseline
func FilterWildcardHTTPResults(results []ProbeResult, wildcardInfo *WildcardInfo) []ProbeResult {
	if !wildcardInfo.IsWildcard || wildcardInfo.BaselineStatus == 0 {
		return results
	}

	var filtered []ProbeResult
	for _, r := range results {
		if isWildcardResponse(r, wildcardInfo) {
			continue
		}
		filtered = append(filtered, r)
	}

	return filtered
}

func isWildcardResponse(result ProbeResult, wildcardInfo *WildcardInfo) bool {
	if result.StatusCode != wildcardInfo.BaselineStatus {
		return false
	}

	if wildcardInfo.BaselineCL > 0 && result.ContentLength > 0 {
		diff := float64(result.ContentLength-wildcardInfo.BaselineCL) / float64(wildcardInfo.BaselineCL)
		if diff > -0.1 && diff < 0.1 {
			return true
		}
	}

	if wildcardInfo.BaselineWords > 0 && result.Words > 0 {
		diff := float64(result.Words-wildcardInfo.BaselineWords) / float64(wildcardInfo.BaselineWords)
		if diff > -0.1 && diff < 0.1 {
			return true
		}
	}

	return false
}

// RunDnsxWithWildcardFilter runs dnsx and filters wildcard results
func RunDnsxWithWildcardFilter(domains []string, target string) ([]string, error) {
	if !CheckDnsxInstalled() {
		return nil, fmt.Errorf("dnsx not installed")
	}

	if len(domains) == 0 {
		return nil, nil
	}

	wildcardInfo := DetectWildcardDNS(target)

	args := []string{
		"-silent",
		"-resp",
		"-retry", "2",
		"-t", "100",
	}

	// -wd flag expects the wildcard domain, not IPs
	// dnsx will automatically filter wildcards when given the domain
	if wildcardInfo.IsWildcard {
		args = append(args, "-wd", target)
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

	if wildcardInfo.IsWildcard {
		resolved = filterWildcardDomains(resolved, wildcardInfo)
	}

	return resolved, nil
}

func filterWildcardDomains(domains []string, wildcardInfo *WildcardInfo) []string {
	if !wildcardInfo.IsWildcard || len(wildcardInfo.WildcardIPs) == 0 {
		return domains
	}

	wildcardIPSet := make(map[string]bool)
	for _, ip := range wildcardInfo.WildcardIPs {
		wildcardIPSet[ip] = true
	}

	var filtered []string
	for _, domain := range domains {
		ips, err := net.LookupHost(domain)
		if err != nil {
			continue
		}

		allWildcard := true
		for _, ip := range ips {
			if !wildcardIPSet[ip] {
				allWildcard = false
				break
			}
		}

		if !allWildcard {
			filtered = append(filtered, domain)
		}
	}

	return filtered
}

func deduplicateStrings(input []string) []string {
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

// WildcardAwareProbe probes domains with wildcard filtering
func WildcardAwareProbe(domains []string, target string) []ProbeResult {
	if len(domains) == 0 {
		return nil
	}

	wildcardInfo := DetectWildcardHTTP(target)
	results := ProbeBatch(domains, target)

	if wildcardInfo.IsWildcard {
		results = FilterWildcardHTTPResults(results, wildcardInfo)
	}

	return results
}

