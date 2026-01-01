package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// HttpxResult represents the JSON output from httpx
type HttpxResult struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	StatusCode    int      `json:"status_code"`
	ContentLength int64    `json:"content_length"`
	ContentType   string   `json:"content_type"`
	Title         string   `json:"title"`
	WebServer     string   `json:"webserver"`
	Technologies  []string `json:"tech"`
	Host          string   `json:"host"`
	Port          string   `json:"port"`
	Scheme        string   `json:"scheme"`
	ResponseTime  string   `json:"time"`
	Words         int      `json:"words"`
	Lines         int      `json:"lines"`
	FinalURL      string   `json:"final_url"`
	Failed        bool     `json:"failed"`
	Error         string   `json:"error"`
}

// ProbeResult contains HTTP probe results for a domain
type ProbeResult struct {
	Domain        string
	Target        string
	URL           string
	StatusCode    int
	ContentLength int64
	Title         string
	Server        string
	Technologies  []string
	ContentType   string
	Words         int
	Lines         int
	ResponseTime  time.Duration
	Error         string
	Timestamp     time.Time
}

// ProbeConfig holds configuration for HTTP probing
type ProbeConfig struct {
	Headers       []string // Custom headers
	UseBypass     bool     // Enable bypass headers
	Timeout       int      // Request timeout
	Threads       int      // Concurrent threads
	FollowRedirect bool    // Follow redirects
	RateLimit     int      // Requests per second (0 = unlimited)
}

// DefaultProbeConfig returns sensible defaults
func DefaultProbeConfig() ProbeConfig {
	return ProbeConfig{
		Headers:        nil,
		UseBypass:      false,
		Timeout:        10,
		Threads:        50,
		FollowRedirect: true,
		RateLimit:      0,
	}
}

// BypassHeaders returns common headers used for 403/404 bypass
func BypassHeaders() []string {
	return []string{
		// IP-based bypasses
		"X-Forwarded-For: 127.0.0.1",
		"X-Forwarded-Host: 127.0.0.1",
		"X-Client-IP: 127.0.0.1",
		"X-Real-IP: 127.0.0.1",
		"X-Originating-IP: 127.0.0.1",
		"X-Remote-IP: 127.0.0.1",
		"X-Remote-Addr: 127.0.0.1",
		"X-Custom-IP-Authorization: 127.0.0.1",
		// URL rewrite bypasses
		"X-Original-URL: /",
		"X-Rewrite-URL: /",
		"X-Override-URL: /",
		// Host header manipulation
		"X-Host: localhost",
		"X-Forwarded-Server: localhost",
		// Other common bypasses
		"X-ProxyUser-Ip: 127.0.0.1",
		"Client-IP: 127.0.0.1",
		"True-Client-IP: 127.0.0.1",
		"Cluster-Client-IP: 127.0.0.1",
		"X-Cluster-Client-IP: 127.0.0.1",
		"Forwarded: for=127.0.0.1;by=127.0.0.1",
	}
}

// Global probe config (can be set from main)
var GlobalProbeConfig = DefaultProbeConfig()

// SetProbeConfig sets the global probe configuration
func SetProbeConfig(cfg ProbeConfig) {
	GlobalProbeConfig = cfg
}

// buildHttpxArgs builds the httpx command arguments
func buildHttpxArgs(cfg ProbeConfig) []string {
	args := []string{
		"-silent",
		"-j",  // JSON output
		"-sc", // status-code
		"-cl", // content-length
		"-title",
		"-server", // web-server
		"-td",     // tech-detect
		"-ct",     // content-type
		"-rt",     // response-time
		"-wc",     // word-count
		"-lc",     // line-count
		"-timeout", fmt.Sprintf("%d", cfg.Timeout),
		"-retries", "2",
	}

	if cfg.FollowRedirect {
		args = append(args, "-fr") // follow-redirects
	}

	if cfg.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", cfg.Threads))
	}

	if cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", cfg.RateLimit))
	}

	// Add custom headers
	for _, header := range cfg.Headers {
		args = append(args, "-H", header)
	}

	// Add bypass headers if enabled
	if cfg.UseBypass {
		for _, header := range BypassHeaders() {
			args = append(args, "-H", header)
		}
	}

	return args
}

// ProbeWithHttpx uses httpx to probe a domain
func ProbeWithHttpx(domain string) ProbeResult {
	return ProbeWithHttpxConfig(domain, GlobalProbeConfig)
}

// ProbeWithHttpxConfig uses httpx to probe a domain with custom config
func ProbeWithHttpxConfig(domain string, cfg ProbeConfig) ProbeResult {
	result := ProbeResult{
		Domain:    domain,
		Timestamp: time.Now(),
	}

	args := buildHttpxArgs(cfg)
	cmd := exec.Command("httpx", args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		result.Error = fmt.Sprintf("failed to create stdin pipe: %v", err)
		return result
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		result.Error = fmt.Sprintf("failed to create stdout pipe: %v", err)
		return result
	}

	if err := cmd.Start(); err != nil {
		result.Error = fmt.Sprintf("failed to start httpx: %v", err)
		return result
	}

	go func() {
		defer stdin.Close()
		fmt.Fprintln(stdin, domain)
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		var httpxResult HttpxResult
		if err := json.Unmarshal([]byte(line), &httpxResult); err != nil {
			continue
		}

		var responseTime time.Duration
		if httpxResult.ResponseTime != "" {
			responseTime, _ = time.ParseDuration(strings.TrimSpace(httpxResult.ResponseTime))
		}

		result.URL = httpxResult.URL
		result.StatusCode = httpxResult.StatusCode
		result.ContentLength = httpxResult.ContentLength
		result.Title = httpxResult.Title
		result.Server = httpxResult.WebServer
		result.Technologies = httpxResult.Technologies
		result.ContentType = httpxResult.ContentType
		result.Words = httpxResult.Words
		result.Lines = httpxResult.Lines
		result.ResponseTime = responseTime

		if httpxResult.Failed {
			result.Error = httpxResult.Error
		}
	}

	cmd.Wait()
	return result
}

// ProbeBatch probes multiple domains using httpx in batch mode
func ProbeBatch(domains []string, target string) []ProbeResult {
	return ProbeBatchConfig(domains, target, GlobalProbeConfig)
}

// ProbeBatchConfig probes multiple domains with custom config
func ProbeBatchConfig(domains []string, target string, cfg ProbeConfig) []ProbeResult {
	if len(domains) == 0 {
		return nil
	}

	var results []ProbeResult

	args := buildHttpxArgs(cfg)
	cmd := exec.Command("httpx", args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}

	if err := cmd.Start(); err != nil {
		return nil
	}

	go func() {
		defer stdin.Close()
		for _, domain := range domains {
			fmt.Fprintln(stdin, domain)
		}
	}()

	batchScanner := bufio.NewScanner(stdout)
	// Increase buffer size to handle large JSON lines (1MB instead of default 64KB)
	batchScanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for batchScanner.Scan() {
		line := batchScanner.Text()
		var httpxResult HttpxResult
		if err := json.Unmarshal([]byte(line), &httpxResult); err != nil {
			continue
		}

		var responseTime time.Duration
		if httpxResult.ResponseTime != "" {
			responseTime, _ = time.ParseDuration(strings.TrimSpace(httpxResult.ResponseTime))
		}

		result := ProbeResult{
			Domain:        httpxResult.Input,
			Target:        target,
			URL:           httpxResult.URL,
			StatusCode:    httpxResult.StatusCode,
			ContentLength: httpxResult.ContentLength,
			Title:         httpxResult.Title,
			Server:        httpxResult.WebServer,
			Technologies:  httpxResult.Technologies,
			ContentType:   httpxResult.ContentType,
			Words:         httpxResult.Words,
			Lines:         httpxResult.Lines,
			ResponseTime:  responseTime,
			Timestamp:     time.Now(),
		}

		if httpxResult.Failed {
			result.Error = httpxResult.Error
		}

		results = append(results, result)
	}

	cmd.Wait()
	return results
}

// CheckHttpxInstalled checks if httpx is available
func CheckHttpxInstalled() bool {
	_, err := exec.LookPath("httpx")
	return err == nil
}
