package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CrtShEntry represents a single entry from crt.sh JSON response
type CrtShEntry struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

// CrtShClient handles queries to crt.sh
type CrtShClient struct {
	httpClient *http.Client
}

// NewCrtShClient creates a new crt.sh client
func NewCrtShClient() *CrtShClient {
	return &CrtShClient{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// QuerySubdomains queries crt.sh for all subdomains of a target
func (c *CrtShClient) QuerySubdomains(target string) ([]string, error) {
	query := fmt.Sprintf("%%.%s", target)
	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(query))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if len(body) == 0 || string(body) == "[]" || string(body) == "null" {
		return []string{}, nil
	}

	var entries []CrtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response: %w", err)
	}

	seen := make(map[string]bool)
	var subdomains []string

	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" {
				continue
			}

			if strings.HasPrefix(name, "*.") {
				name = strings.TrimPrefix(name, "*.")
			}

			if !IsValidSubdomain(name, target) {
				continue
			}

			if !seen[name] {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}

		cn := strings.TrimSpace(strings.ToLower(entry.CommonName))
		if cn != "" {
			if strings.HasPrefix(cn, "*.") {
				cn = strings.TrimPrefix(cn, "*.")
			}
			if IsValidSubdomain(cn, target) && !seen[cn] {
				seen[cn] = true
				subdomains = append(subdomains, cn)
			}
		}
	}

	return subdomains, nil
}

// IsValidSubdomain checks if a domain is a valid subdomain of the target
func IsValidSubdomain(domain, target string) bool {
	domain = strings.ToLower(domain)
	target = strings.ToLower(target)

	if domain == target {
		return true
	}

	if strings.HasSuffix(domain, "."+target) {
		return true
	}

	return false
}

