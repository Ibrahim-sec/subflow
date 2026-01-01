package scanner

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PatternType represents the type of subdomain pattern
type PatternType string

const (
	PatternPrefix    PatternType = "prefix"    // dev.X.domain.com → dev.{word}.domain.com
	PatternSuffix    PatternType = "suffix"    // X.dev.domain.com → {word}.dev.domain.com
	PatternDashLeft  PatternType = "dash-left" // dev-X.domain.com → dev-{word}.domain.com
	PatternDashRight PatternType = "dash-right" // X-dev.domain.com → {word}-dev.domain.com
)

// DetectedPattern represents a discovered pattern in subdomains
type DetectedPattern struct {
	Keyword   string
	Type      PatternType
	Count     int      // How many times this pattern was seen
	Examples  []string // Example subdomains matching this pattern
	AlterxCmd string   // The alterx pattern to use
}

// SmartAlterxConfig configures smart alterx behavior
type SmartAlterxConfig struct {
	MinOccurrences int // Minimum times a pattern must appear (default: 2)
	MaxKeywords    int // Maximum keywords to process (default: 10)
}

// DefaultSmartAlterxConfig returns sensible defaults
func DefaultSmartAlterxConfig() SmartAlterxConfig {
	return SmartAlterxConfig{
		MinOccurrences: 2,
		MaxKeywords:    10,
	}
}

// AnalyzeSubdomainPatterns analyzes subdomains to find recurring patterns
func AnalyzeSubdomainPatterns(subdomains []string, baseDomain string) []DetectedPattern {
	baseDomain = strings.ToLower(baseDomain)
	
	// Track pattern occurrences
	prefixPatterns := make(map[string][]string)    // keyword → examples
	suffixPatterns := make(map[string][]string)
	dashLeftPatterns := make(map[string][]string)
	dashRightPatterns := make(map[string][]string)

	for _, sub := range subdomains {
		sub = strings.ToLower(sub)
		
		// Remove the base domain to get the subdomain parts
		if !strings.HasSuffix(sub, "."+baseDomain) && sub != baseDomain {
			continue
		}
		
		prefix := strings.TrimSuffix(sub, "."+baseDomain)
		if prefix == "" || prefix == sub {
			continue
		}

		parts := strings.Split(prefix, ".")
		
		// Analyze dot-separated patterns (multi-level subdomains)
		if len(parts) >= 2 {
			// Check for prefix patterns: dev.X.domain.com
			// The first part appears with different second parts
			firstPart := parts[0]
			if isValidKeyword(firstPart) {
				prefixPatterns[firstPart] = append(prefixPatterns[firstPart], sub)
			}

			// Check for suffix patterns: X.dev.domain.com
			// The last part (before base domain) appears with different prefixes
			lastPart := parts[len(parts)-1]
			if isValidKeyword(lastPart) {
				suffixPatterns[lastPart] = append(suffixPatterns[lastPart], sub)
			}
		}

		// Analyze dash-separated patterns in the first part
		if len(parts) >= 1 {
			firstPart := parts[0]
			dashParts := strings.Split(firstPart, "-")
			
			if len(dashParts) >= 2 {
				// Check for dash-left patterns: dev-X.domain.com
				leftKeyword := dashParts[0]
				if isValidKeyword(leftKeyword) {
					dashLeftPatterns[leftKeyword] = append(dashLeftPatterns[leftKeyword], sub)
				}

				// Check for dash-right patterns: X-dev.domain.com
				rightKeyword := dashParts[len(dashParts)-1]
				if isValidKeyword(rightKeyword) {
					dashRightPatterns[rightKeyword] = append(dashRightPatterns[rightKeyword], sub)
				}
			}
		}
	}

	// Convert to detected patterns and filter by minimum occurrences
	var patterns []DetectedPattern
	cfg := DefaultSmartAlterxConfig()

	// Process prefix patterns
	for keyword, examples := range prefixPatterns {
		if len(examples) >= cfg.MinOccurrences {
			patterns = append(patterns, DetectedPattern{
				Keyword:   keyword,
				Type:      PatternPrefix,
				Count:     len(examples),
				Examples:  limitExamples(examples, 3),
				AlterxCmd: "{{word}}." + keyword + ".{{suffix}}",
			})
		}
	}

	// Process suffix patterns
	for keyword, examples := range suffixPatterns {
		if len(examples) >= cfg.MinOccurrences {
			patterns = append(patterns, DetectedPattern{
				Keyword:   keyword,
				Type:      PatternSuffix,
				Count:     len(examples),
				Examples:  limitExamples(examples, 3),
				AlterxCmd: keyword + ".{{word}}.{{suffix}}",
			})
		}
	}

	// Process dash-left patterns
	for keyword, examples := range dashLeftPatterns {
		if len(examples) >= cfg.MinOccurrences {
			patterns = append(patterns, DetectedPattern{
				Keyword:   keyword,
				Type:      PatternDashLeft,
				Count:     len(examples),
				Examples:  limitExamples(examples, 3),
				AlterxCmd: keyword + "-{{word}}.{{suffix}}",
			})
		}
	}

	// Process dash-right patterns
	for keyword, examples := range dashRightPatterns {
		if len(examples) >= cfg.MinOccurrences {
			patterns = append(patterns, DetectedPattern{
				Keyword:   keyword,
				Type:      PatternDashRight,
				Count:     len(examples),
				Examples:  limitExamples(examples, 3),
				AlterxCmd: "{{word}}-" + keyword + ".{{suffix}}",
			})
		}
	}

	// Sort by count (most common patterns first)
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].Count > patterns[j].Count
	})

	// Limit to top patterns
	if len(patterns) > cfg.MaxKeywords {
		patterns = patterns[:cfg.MaxKeywords]
	}

	return patterns
}

// isValidKeyword checks if a string is a valid keyword for pattern matching
func isValidKeyword(s string) bool {
	s = strings.TrimSpace(s)
	
	// Must be at least 2 characters
	if len(s) < 2 {
		return false
	}
	
	// Must not be too long
	if len(s) > 20 {
		return false
	}

	// Must not be purely numeric
	if isNumeric(s) {
		return false
	}

	// Must be alphanumeric (no special chars except common ones)
	validPattern := regexp.MustCompile(`^[a-z0-9]+$`)
	if !validPattern.MatchString(s) {
		return false
	}

	// Skip common non-informative keywords
	skipKeywords := map[string]bool{
		"www": true, "mail": true, "ftp": true, "smtp": true,
		"pop": true, "imap": true, "ns": true, "dns": true,
		"mx": true, "com": true, "net": true, "org": true,
	}
	if skipKeywords[s] {
		return false
	}

	return true
}

// isNumeric checks if a string is purely numeric
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// limitExamples limits the number of examples
func limitExamples(examples []string, max int) []string {
	if len(examples) <= max {
		return examples
	}
	return examples[:max]
}

// GenerateSmartAlterxPatterns generates alterx patterns based on detected patterns
func GenerateSmartAlterxPatterns(patterns []DetectedPattern, wordlist string) []AlterxPattern {
	var alterxPatterns []AlterxPattern

	for _, p := range patterns {
		alterxPatterns = append(alterxPatterns, AlterxPattern{
			Pattern:  p.AlterxCmd,
			WordList: wordlist,
		})
	}

	return alterxPatterns
}

// SmartAlterx runs alterx only on detected high-value patterns
func SmartAlterx(subdomains []string, baseDomain string, wordlist string) ([]string, []DetectedPattern) {
	// Analyze patterns
	patterns := AnalyzeSubdomainPatterns(subdomains, baseDomain)
	
	if len(patterns) == 0 {
		return nil, nil
	}

	// Generate alterx patterns from detected patterns
	alterxPatterns := GenerateSmartAlterxPatterns(patterns, wordlist)

	// Run alterx with the smart patterns
	results := RunAlterxParallel(subdomains, alterxPatterns)

	return results, patterns
}

// GetPatternSummary returns a human-readable summary of detected patterns
func GetPatternSummary(patterns []DetectedPattern) string {
	if len(patterns) == 0 {
		return "No significant patterns detected"
	}

	var sb strings.Builder
	sb.WriteString("Detected patterns:\n")
	
	for _, p := range patterns {
		sb.WriteString("  • ")
		sb.WriteString(p.Keyword)
		sb.WriteString(" (")
		sb.WriteString(string(p.Type))
		sb.WriteString(", ")
		sb.WriteString(fmt.Sprintf("%d", p.Count))
		sb.WriteString("x) → ")
		sb.WriteString(p.AlterxCmd)
		sb.WriteString("\n")
		sb.WriteString("    Examples: ")
		sb.WriteString(strings.Join(p.Examples, ", "))
		sb.WriteString("\n")
	}

	return sb.String()
}

