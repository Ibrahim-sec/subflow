package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/ibrahim-sec/subflow/internal/config"
	"github.com/ibrahim-sec/subflow/internal/discovery"
	"github.com/ibrahim-sec/subflow/internal/notify"
	"github.com/ibrahim-sec/subflow/internal/output"
	"github.com/ibrahim-sec/subflow/internal/scanner"
	"github.com/ibrahim-sec/subflow/internal/store"
)

const version = "3.0.0"

var (
	// Target flags
	target     = flag.String("target", "", "target domain(s)")
	configPath = flag.String("config", "", "config file path")

	// Discovery flags
	subfinderFlag = flag.Bool("subfinder", false, "use subfinder")
	alterxFlag    = flag.Bool("alterx", false, "use alterx permutations")
	wordlistFlag  = flag.String("wordlist", "subdomains-10000.txt", "wordlist file for alterx")

	// Scanning flags
	probeFlag = flag.Bool("probe", false, "enable httpx probing")
	portsFlag = flag.String("ports", "", "port scan with naabu")
	fullFlag  = flag.Bool("full", false, "run full pipeline")

	// Monitoring flags
	monitorFlag  = flag.Bool("monitor", false, "continuous monitoring")
	watchFlag    = flag.Bool("watch", false, "watch for changes")
	intervalFlag = flag.Int("interval", 30, "polling interval (minutes)")

	// Output flags
	outputFlag = flag.String("output", "", "output file path")
	formatFlag = flag.String("format", "txt", "output format: txt, json, csv")
	silentFlag = flag.Bool("silent", false, "silent mode (domains only)")

	// Processing flags
	threadsFlag = flag.Int("threads", 1, "parallel target processing")
	resumeFlag  = flag.Bool("resume", false, "resume interrupted scan")

	// HTTP probing flags
	headersFlag   = flag.String("headers", "", "custom headers (comma-separated: 'H1:V1,H2:V2')")
	bypassFlag    = flag.Bool("bypass", false, "use 403/404 bypass headers")
	rateLimitFlag = flag.Int("rate-limit", 0, "requests per second (0=unlimited)")
	timeoutFlag   = flag.Int("timeout", 10, "HTTP timeout in seconds")

	// Storage and notification
	dbPath       = flag.String("db", "", "database path")
	notifyOption = flag.String("notify", "", "discord, telegram, both")

	// Other flags
	showVersion = flag.Bool("version", false, "show version")
	showHelp    = flag.Bool("h", false, "show help")
	showHelp2   = flag.Bool("help", false, "show help")

	// Logger
	logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: true,
		TimeFormat:      "15:04:05",
		Level:           log.DebugLevel,
	})
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("subflow v%s\n", version)
		return
	}

	if *showHelp || *showHelp2 {
		displayHelp()
		return
	}

	if !*silentFlag {
		printBanner()
	}

	// Load configuration
	if *configPath != "" {
		config.SetConfigPath(*configPath)
	}

	if *dbPath != "" {
		store.CustomDBPath = *dbPath
	}

	// Handle -full flag
	if *fullFlag {
		*subfinderFlag = true
		*alterxFlag = true
		*probeFlag = true
		if *portsFlag == "" {
			*portsFlag = config.DefaultPorts()
		}
	}

	// Configure HTTP probing
	probeConfig := scanner.DefaultProbeConfig()
	probeConfig.UseBypass = *bypassFlag
	probeConfig.Timeout = *timeoutFlag
	probeConfig.RateLimit = *rateLimitFlag

	// Parse custom headers
	if *headersFlag != "" {
		headers := strings.Split(*headersFlag, ",")
		for _, h := range headers {
			h = strings.TrimSpace(h)
			if h != "" {
				probeConfig.Headers = append(probeConfig.Headers, h)
			}
		}
	}

	scanner.SetProbeConfig(probeConfig)

	if *bypassFlag && !*silentFlag {
		logger.Info("bypass headers enabled", "count", len(scanner.BypassHeaders()))
	}

	// Check required tools
	if !checkRequiredTools() {
		return
	}

	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("failed to load config", "error", err)
	}

	// Load targets
	targets := loadTargets(cfg)
	if len(targets) == 0 {
		logger.Fatal("no targets provided")
	}

	// Setup notifications
	setupNotifications(cfg)

	// Setup output
	outputWriter, err := output.NewWriter(*outputFlag, *formatFlag)
	if err != nil {
		logger.Fatal("failed to create output writer", "error", err)
	}
	defer func() {
		if outputWriter != nil {
			outputWriter.Close()
		}
	}()

	// Setup context
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		if !*silentFlag {
			logger.Info("shutting down...")
		}
		store.Close()
		cancel()
	}()

	if !*silentFlag {
		logger.Info("starting subflow", "version", version, "targets", len(targets))
		
		// Check database status
		if working, err := store.GetDBStatus(); !working {
			logger.Warn("database not available - deduplication and change detection disabled", "error", err)
			logger.Warn("install sqlite3: sudo apt-get install libsqlite3-dev (for database features)")
		}
	}

	// Run pipeline
	runPipeline(ctx, targets, outputWriter)
}

func runPipeline(ctx context.Context, targets []string, outputWriter *output.Writer) {
	pipelineConfig := PipelineConfig{
		UseSubfinder: *subfinderFlag,
		UseAlterx:    *alterxFlag,
		UsePorts:     *portsFlag != "",
		UseProbe:     *probeFlag,
		Ports:        *portsFlag,
		Resume:       *resumeFlag,
	}

	if *threadsFlag > 1 {
		// Parallel processing
		runParallelPipeline(ctx, targets, pipelineConfig, *threadsFlag, outputWriter)
	} else {
		// Sequential processing
		for _, target := range targets {
			select {
			case <-ctx.Done():
				return
			default:
			}
			runTargetPipeline(ctx, target, pipelineConfig, outputWriter)
		}
	}

	// Monitoring loop
	if *monitorFlag {
		runMonitoringLoop(ctx, targets, pipelineConfig, outputWriter)
	}
}

// PipelineConfig holds pipeline configuration
type PipelineConfig struct {
	UseSubfinder bool
	UseAlterx    bool
	UsePorts     bool
	UseProbe     bool
	Ports        string
	Resume       bool
}

func runTargetPipeline(ctx context.Context, target string, cfg PipelineConfig, outputWriter *output.Writer) {
	if !*silentFlag {
		logger.Info("processing target", "target", target)
	}

	// Check for resume
	if cfg.Resume {
		phase, processed, lastDomain, found := store.GetScanState(target)
		if found {
			logger.Info("resuming scan", "target", target, "phase", phase, "processed", processed, "last", lastDomain)
		}
	}

	// ============================================================
	// STAGE 1: crt.sh + subfinder → notify new subdomains
	// ============================================================
	if !*silentFlag {
		logger.Info("STAGE 1: passive discovery (crt.sh + subfinder)", "target", target)
	}

	var discoveryDomains []string

	// crt.sh discovery
	client := discovery.NewCrtShClient()
	crtshDomains, err := client.QuerySubdomains(target)
	if err != nil {
		if !*silentFlag {
			logger.Warn("crt.sh failed", "error", err)
		}
	} else {
		discoveryDomains = append(discoveryDomains, crtshDomains...)
		if !*silentFlag {
			logger.Debug("crt.sh", "count", len(crtshDomains))
		}
	}

	// Subfinder discovery
	if cfg.UseSubfinder && discovery.CheckToolInstalled("subfinder") {
		subfinderDomains, err := discovery.RunSubfinder(target)
		if err == nil {
			discoveryDomains = append(discoveryDomains, subfinderDomains...)
			if !*silentFlag {
				logger.Debug("subfinder", "count", len(subfinderDomains))
			}
		}
	}

	// Deduplicate discovery results
	discoveryDomains = discovery.DeduplicateStrings(discoveryDomains)
	discoveryDomains = discovery.FilterNumericSubdomains(discoveryDomains)

	// Check for NEW domains from discovery stage
	var newDiscoveryDomains []string
	for _, domain := range discoveryDomains {
		if store.IsNewDomain(domain) {
			newDiscoveryDomains = append(newDiscoveryDomains, domain)
		}
	}

	if !*silentFlag {
		logger.Info("STAGE 1 complete", "total", len(discoveryDomains), "new", len(newDiscoveryDomains))
	}

	// NOTIFY: new subdomains from discovery stage
	if len(newDiscoveryDomains) > 0 {
		notifyNewDomains(newDiscoveryDomains, target, "discovery")
	}

	// ============================================================
	// STAGE 2: SMART alterx + dnsx → notify new subdomains
	// ============================================================
	var alterxDomains []string

	if cfg.UseAlterx && scanner.CheckAlterxInstalled() && scanner.CheckDnsxInstalled() {
		if !*silentFlag {
			logger.Info("STAGE 2: smart permutation (alterx + dnsx)", "target", target)
		}

		// Detect wildcard
		wildcardInfo := scanner.DetectWildcardDNS(target)
		if wildcardInfo.IsWildcard && !*silentFlag {
			logger.Warn("wildcard DNS detected - filtering enabled", "target", target)
		}

		// SMART ALTERX: Analyze patterns in discovered subdomains
		detectedPatterns := scanner.AnalyzeSubdomainPatterns(discoveryDomains, target)
		
		var permutations []string
		
		if len(detectedPatterns) > 0 {
			// We found patterns! Use smart alterx
			if !*silentFlag {
				logger.Info("detected subdomain patterns", "count", len(detectedPatterns))
				for _, p := range detectedPatterns {
					logger.Debug("pattern found",
						"keyword", p.Keyword,
						"type", string(p.Type),
						"occurrences", p.Count,
						"alterx", p.AlterxCmd,
					)
				}
			}

			// Generate patterns based on detected keywords
			smartPatterns := scanner.GenerateSmartAlterxPatterns(detectedPatterns, *wordlistFlag)
			
			// Also add some base patterns for the domain itself
			basePatterns := []scanner.AlterxPattern{
				{Pattern: "{{word}}.{{suffix}}", WordList: *wordlistFlag},
			}
			smartPatterns = append(smartPatterns, basePatterns...)

			permutations = scanner.RunAlterxParallel(discoveryDomains, smartPatterns)
			
			if !*silentFlag {
				logger.Debug("smart alterx permutations", "patterns_used", len(smartPatterns), "generated", len(permutations))
			}
		} else {
			// No patterns detected, use minimal default patterns
			if !*silentFlag {
				logger.Debug("no patterns detected, using default alterx")
			}
			
			defaultPatterns := []scanner.AlterxPattern{
				{Pattern: "{{word}}.{{suffix}}", WordList: *wordlistFlag},
				{Pattern: "{{word}}-{{sub}}.{{suffix}}", WordList: *wordlistFlag},
				{Pattern: "{{sub}}-{{word}}.{{suffix}}", WordList: *wordlistFlag},
			}
			permutations = scanner.RunAlterxParallel(discoveryDomains, defaultPatterns)
		}

		if !*silentFlag {
			logger.Debug("alterx permutations generated", "count", len(permutations))
		}

		// Validate with dnsx (with wildcard filtering)
		var validated []string
		if wildcardInfo.IsWildcard {
			validated, _ = scanner.RunDnsxWithWildcardFilter(permutations, target)
		} else {
			validated, _ = scanner.RunDnsx(permutations)
		}

		// Check for NEW domains from alterx stage
		var newAlterxDomains []string
		for _, domain := range validated {
			if store.IsNewDomain(domain) {
				newAlterxDomains = append(newAlterxDomains, domain)
				alterxDomains = append(alterxDomains, domain)
			}
		}

		if !*silentFlag {
			logger.Info("STAGE 2 complete", 
				"patterns_detected", len(detectedPatterns),
				"generated", len(permutations), 
				"valid", len(validated), 
				"new", len(newAlterxDomains),
			)
		}

		// NOTIFY: new subdomains from alterx stage
		if len(newAlterxDomains) > 0 {
			notifyNewDomains(newAlterxDomains, target, "alterx")
		}
	}

	// ============================================================
	// STAGE 3: Gather ALL unique domains → naabu + httpx
	// ============================================================
	
	// Combine all domains: discovery + alterx (already deduplicated and stored)
	allUniqueDomains := discovery.DeduplicateStrings(append(discoveryDomains, alterxDomains...))
	
	// Get only NEW domains for scanning (not seen before this run)
	var domainsToScan []string
	domainsToScan = append(domainsToScan, newDiscoveryDomains...)
	domainsToScan = append(domainsToScan, alterxDomains...) // alterxDomains already filtered for new
	domainsToScan = discovery.DeduplicateStrings(domainsToScan)

	if len(domainsToScan) == 0 {
		if !*silentFlag {
			logger.Info("no new domains to scan", "target", target)
		}
		return
	}

	if !*silentFlag {
		logger.Info("STAGE 3: scanning (naabu + httpx)", "target", target, "domains", len(domainsToScan))
	}

	// Port scanning with naabu
	var probeTargets []string
	if cfg.UsePorts && scanner.CheckNaabuInstalled() {
		if !*silentFlag {
			logger.Info("running naabu port scan", "domains", len(domainsToScan))
		}
		ports := cfg.Ports
		if ports == "" {
			ports = config.DefaultPorts()
		}
		portResults, err := scanner.RunNaabu(domainsToScan, ports)
		if err != nil {
			if !*silentFlag {
				logger.Warn("naabu failed", "error", err)
			}
		} else if len(portResults) > 0 {
			probeTargets = portResults
			if !*silentFlag {
				logger.Debug("naabu results", "count", len(portResults))
			}
		}
	}

	// If no port scan results, probe the domains directly
	if len(probeTargets) == 0 {
		probeTargets = domainsToScan
	}

	// HTTP probing with httpx
	if cfg.UseProbe && scanner.CheckHttpxInstalled() {
		if !*silentFlag {
			logger.Info("running httpx probe", "targets", len(probeTargets))
		}

		results := scanner.WildcardAwareProbe(probeTargets, target)

		if !*silentFlag {
			logger.Info("STAGE 3 complete", "probed", len(results))
		}

		for _, r := range results {
			// Output to console
			if *silentFlag {
				if r.URL != "" {
					fmt.Println(r.URL)
				} else {
					fmt.Println(r.Domain)
				}
			} else {
				logger.Info("live",
					"url", r.URL,
					"status", r.StatusCode,
					"cl", r.ContentLength,
					"title", truncate(r.Title, 30),
				)
			}

			// Write to file
			if outputWriter != nil {
				outputWriter.Write(output.Result{
					Domain:        r.Domain,
					Target:        target,
					URL:           r.URL,
					StatusCode:    r.StatusCode,
					ContentLength: r.ContentLength,
					Title:         r.Title,
					Server:        r.Server,
					Technologies:  r.Technologies,
					Timestamp:     r.Timestamp,
				})
			}

			// Store probe result
			store.StoreProbeResult(
				r.Domain,
				r.URL,
				r.StatusCode,
				r.ContentLength,
				r.Title,
				r.Server,
				strings.Join(r.Technologies, ","),
				r.ResponseTime.Milliseconds(),
				r.Error,
			)

			// Send detailed notification for live hosts
			if r.Error == "" {
				sendProbeNotification(r, target)
			}
		}
	} else {
		// No probing - just output domains
		for _, domain := range domainsToScan {
			if *silentFlag {
				fmt.Println(domain)
			}

			if outputWriter != nil {
				outputWriter.Write(output.Result{
					Domain:    domain,
					Target:    target,
					Timestamp: time.Now(),
				})
			}
		}
	}

	// Clear resume state
	if cfg.Resume {
		store.ClearScanState(target)
	}

	if !*silentFlag {
		logger.Info("pipeline complete", "target", target, "total_unique", len(allUniqueDomains))
	}
}

// notifyNewDomains sends a batch notification for new domains
func notifyNewDomains(domains []string, target, stage string) {
	if len(domains) == 0 {
		return
	}

	if !*silentFlag {
		logger.Info("notifying new domains", "stage", stage, "count", len(domains))
	}

	// Send to Discord
	if webhookURL != "" {
		notify.SendDiscord(strings.Join(domains, "\n"), target)
	}

	// Send to Telegram  
	if telegramEnabled {
		notify.SendTelegram(target, domains)
	}
}

// sendProbeNotification sends detailed notification for a probed domain
func sendProbeNotification(result scanner.ProbeResult, target string) {
	if webhookURL == "" && !telegramEnabled {
		return
	}

	// Build rich notification
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("🎯 Live: %s", result.Domain),
				"description": result.URL,
				"color":       getStatusColor(result.StatusCode),
				"fields": []map[string]interface{}{
					{"name": "Status", "value": fmt.Sprintf("`%d`", result.StatusCode), "inline": true},
					{"name": "Size", "value": fmt.Sprintf("`%d`", result.ContentLength), "inline": true},
					{"name": "Title", "value": truncate(result.Title, 50), "inline": false},
				},
				"footer":    map[string]string{"text": fmt.Sprintf("Target: %s", target)},
				"timestamp": time.Now().Format(time.RFC3339),
			},
		},
	}

	if webhookURL != "" {
		jsonData, _ := json.Marshal(payload)
		notify.SendDiscordWebhook(webhookURL, jsonData)
	}
}

func getStatusColor(status int) int {
	switch {
	case status >= 200 && status < 300:
		return 3066993 // Green
	case status >= 300 && status < 400:
		return 15105570 // Orange
	case status >= 400:
		return 15158332 // Red
	default:
		return 2829617 // Blue
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

var telegramEnabled bool

func runParallelPipeline(ctx context.Context, targets []string, cfg PipelineConfig, threads int, outputWriter *output.Writer) {
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			runTargetPipeline(ctx, t, cfg, outputWriter)
		}(target)
	}

	wg.Wait()
}

func runMonitoringLoop(ctx context.Context, targets []string, cfg PipelineConfig, outputWriter *output.Writer) {
	interval := time.Duration(*intervalFlag) * time.Minute

	if !*silentFlag {
		logger.Info("monitoring mode", "interval", interval)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !*silentFlag {
				logger.Info("monitoring cycle")
			}

			for _, target := range targets {
				runTargetPipeline(ctx, target, cfg, outputWriter)

				if *watchFlag {
					// Re-probe existing domains
					domains := store.GetAllKnownDomains(target)
					if len(domains) > 0 && scanner.CheckHttpxInstalled() {
						results := scanner.WildcardAwareProbe(domains, target)
						for _, r := range results {
							checkForChanges(r, target)
						}
					}
				}
			}
		}
	}
}

// ChangeThresholds defines minimum thresholds for significant changes
type ChangeThresholds struct {
	MinContentLengthDiff   int64   // Minimum absolute CL difference (bytes)
	MinContentLengthPct    float64 // Minimum percentage change
	MinWordsDiff           int     // Minimum word count difference
	MinLinesDiff           int     // Minimum lines difference
}

// DefaultThresholds returns sensible defaults to avoid false positives
func DefaultThresholds() ChangeThresholds {
	return ChangeThresholds{
		MinContentLengthDiff: 500,  // At least 500 bytes difference
		MinContentLengthPct:  0.30, // At least 30% change
		MinWordsDiff:         50,   // At least 50 words difference
		MinLinesDiff:         20,   // At least 20 lines difference
	}
}

// ChangeType represents the type and severity of a change
type ChangeType struct {
	Type        string // "status", "content", "title", "new_endpoint"
	Severity    string // "critical", "high", "medium", "low"
	Description string
	OldValue    string
	NewValue    string
}

func checkForChanges(result scanner.ProbeResult, target string) {
	oldStatus, oldCL, oldTitle, found := store.GetLastProbeResult(result.Domain)
	if !found {
		return
	}

	thresholds := DefaultThresholds()
	var changes []ChangeType

	// ===========================================
	// STATUS CODE CHANGES (Most Important)
	// ===========================================
	if oldStatus != result.StatusCode && oldStatus != 0 && result.StatusCode != 0 {
		change := ChangeType{
			Type:     "status",
			OldValue: fmt.Sprintf("%d", oldStatus),
			NewValue: fmt.Sprintf("%d", result.StatusCode),
		}

		// Determine severity based on status transition
		switch {
		// CRITICAL: Potential auth bypass or new access
		case (oldStatus == 403 || oldStatus == 401) && (result.StatusCode == 200 || result.StatusCode == 301 || result.StatusCode == 302):
			change.Severity = "critical"
			change.Description = fmt.Sprintf("🔴 CRITICAL: Auth bypass? %d → %d", oldStatus, result.StatusCode)

		// HIGH: New endpoint appeared (was 404, now accessible)
		case oldStatus == 404 && result.StatusCode >= 200 && result.StatusCode < 400:
			change.Severity = "high"
			change.Description = fmt.Sprintf("🟠 HIGH: New endpoint! %d → %d", oldStatus, result.StatusCode)

		// HIGH: Endpoint removed or broken
		case oldStatus >= 200 && oldStatus < 400 && result.StatusCode == 404:
			change.Severity = "high"
			change.Description = fmt.Sprintf("🟠 HIGH: Endpoint removed %d → %d (check wayback)", oldStatus, result.StatusCode)

		// HIGH: Server error appeared
		case result.StatusCode >= 500:
			change.Severity = "high"
			change.Description = fmt.Sprintf("🟠 HIGH: Server error! %d → %d", oldStatus, result.StatusCode)

		// MEDIUM: Other status changes
		default:
			change.Severity = "medium"
			change.Description = fmt.Sprintf("🟡 MEDIUM: Status changed %d → %d", oldStatus, result.StatusCode)
		}

		changes = append(changes, change)
	}

	// ===========================================
	// CONTENT LENGTH CHANGES (Significant only)
	// ===========================================
	if oldCL > 0 && result.ContentLength > 0 {
		absDiff := result.ContentLength - oldCL
		if absDiff < 0 {
			absDiff = -absDiff
		}

		pctDiff := float64(result.ContentLength-oldCL) / float64(oldCL)
		if pctDiff < 0 {
			pctDiff = -pctDiff
		}

		// Only alert if BOTH absolute AND percentage thresholds are exceeded
		if absDiff >= thresholds.MinContentLengthDiff && pctDiff >= thresholds.MinContentLengthPct {
			change := ChangeType{
				Type:     "content",
				OldValue: fmt.Sprintf("%d bytes", oldCL),
				NewValue: fmt.Sprintf("%d bytes", result.ContentLength),
			}

			// Determine severity based on magnitude of change
			switch {
			case pctDiff >= 0.80: // 80%+ change
				change.Severity = "high"
				change.Description = fmt.Sprintf("🟠 HIGH: Major content change (%.0f%%) %d → %d bytes", pctDiff*100, oldCL, result.ContentLength)
			case pctDiff >= 0.50: // 50%+ change
				change.Severity = "medium"
				change.Description = fmt.Sprintf("🟡 MEDIUM: Significant content change (%.0f%%) %d → %d bytes", pctDiff*100, oldCL, result.ContentLength)
			default: // 30-50% change
				change.Severity = "low"
				change.Description = fmt.Sprintf("🟢 LOW: Content changed (%.0f%%) %d → %d bytes", pctDiff*100, oldCL, result.ContentLength)
			}

			changes = append(changes, change)
		}
	}

	// ===========================================
	// TITLE CHANGES (Only if significant)
	// ===========================================
	if oldTitle != result.Title && oldTitle != "" && result.Title != "" {
		// Calculate how different the titles are
		if !isSimilarTitle(oldTitle, result.Title) {
			change := ChangeType{
				Type:        "title",
				Severity:    "medium",
				OldValue:    oldTitle,
				NewValue:    result.Title,
				Description: fmt.Sprintf("🟡 MEDIUM: Title changed: '%s' → '%s'", truncate(oldTitle, 30), truncate(result.Title, 30)),
			}
			changes = append(changes, change)
		}
	}

	// ===========================================
	// LOG AND NOTIFY CHANGES
	// ===========================================
	for _, change := range changes {
		if !*silentFlag {
			logger.Warn(change.Description, "domain", result.Domain, "url", result.URL)
		}

		// Send notification for high/critical changes
		if change.Severity == "critical" || change.Severity == "high" {
			sendChangeNotification(result, target, change)
		}
	}

	// Store the new probe result
	store.StoreProbeResult(
		result.Domain,
		result.URL,
		result.StatusCode,
		result.ContentLength,
		result.Title,
		result.Server,
		strings.Join(result.Technologies, ","),
		result.ResponseTime.Milliseconds(),
		result.Error,
	)
}

// isSimilarTitle checks if two titles are essentially the same (ignoring minor differences)
func isSimilarTitle(a, b string) bool {
	// Normalize titles
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))

	if a == b {
		return true
	}

	// Check if one contains the other (common with dynamic titles)
	if strings.Contains(a, b) || strings.Contains(b, a) {
		return true
	}

	// Calculate simple similarity (Jaccard-like)
	wordsA := strings.Fields(a)
	wordsB := strings.Fields(b)

	if len(wordsA) == 0 || len(wordsB) == 0 {
		return false
	}

	// Count common words
	wordSet := make(map[string]bool)
	for _, w := range wordsA {
		wordSet[w] = true
	}

	common := 0
	for _, w := range wordsB {
		if wordSet[w] {
			common++
		}
	}

	// If more than 70% words are common, consider similar
	similarity := float64(common) / float64(max(len(wordsA), len(wordsB)))
	return similarity > 0.7
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// sendChangeNotification sends a detailed notification about a detected change
func sendChangeNotification(result scanner.ProbeResult, target string, change ChangeType) {
	if webhookURL == "" && !telegramEnabled {
		return
	}

	// Color based on severity
	var color int
	var emoji string
	switch change.Severity {
	case "critical":
		color = 15158332 // Red
		emoji = "🔴"
	case "high":
		color = 15105570 // Orange
		emoji = "🟠"
	case "medium":
		color = 16776960 // Yellow
		emoji = "🟡"
	default:
		color = 3066993 // Green
		emoji = "🟢"
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("%s CHANGE DETECTED: %s", emoji, result.Domain),
				"description": change.Description,
				"color":       color,
				"fields": []map[string]interface{}{
					{"name": "URL", "value": result.URL, "inline": false},
					{"name": "Change Type", "value": fmt.Sprintf("`%s`", change.Type), "inline": true},
					{"name": "Severity", "value": fmt.Sprintf("`%s`", strings.ToUpper(change.Severity)), "inline": true},
					{"name": "Old Value", "value": fmt.Sprintf("`%s`", change.OldValue), "inline": true},
					{"name": "New Value", "value": fmt.Sprintf("`%s`", change.NewValue), "inline": true},
					{"name": "Current Status", "value": fmt.Sprintf("`%d`", result.StatusCode), "inline": true},
					{"name": "Current Size", "value": fmt.Sprintf("`%d`", result.ContentLength), "inline": true},
				},
				"footer":    map[string]string{"text": fmt.Sprintf("Target: %s | Investigate immediately if critical!", target)},
				"timestamp": time.Now().Format(time.RFC3339),
			},
		},
	}

	if webhookURL != "" {
		jsonData, _ := json.Marshal(payload)
		notify.SendDiscordWebhook(webhookURL, jsonData)
	}

	// Telegram notification
	if telegramEnabled {
		msg := fmt.Sprintf("%s *CHANGE DETECTED*\n\nDomain: `%s`\nURL: %s\n\n%s\n\nOld: `%s`\nNew: `%s`\n\n_Target: %s_",
			emoji, result.Domain, result.URL, change.Description, change.OldValue, change.NewValue, target)
		notify.SendTelegramMessage(msg)
	}
}

var webhookURL string

func setupNotifications(cfg *config.Config) {
	if cfg == nil {
		return
	}

	webhookURL = strings.TrimSpace(cfg.Webhook)

	if cfg.TelegramBotToken != "" && cfg.TelegramChatID != "" {
		notify.InitTelegram(cfg.TelegramBotToken, cfg.TelegramChatID)
		telegramEnabled = true
	}

	if webhookURL != "" {
		notify.InitDiscord(webhookURL)
	}
}

func loadTargets(cfg *config.Config) []string {
	// Check stdin
	if fi, _ := os.Stdin.Stat(); (fi.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		var targets []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		if len(targets) > 0 {
			return targets
		}
	}

	// Check -target flag
	if *target != "" {
		if info, err := os.Stat(*target); err == nil && !info.IsDir() {
			file, err := os.Open(*target)
			if err == nil {
				defer file.Close()
				scanner := bufio.NewScanner(file)
				var targets []string
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line != "" && !strings.HasPrefix(line, "#") {
						targets = append(targets, line)
					}
				}
				return targets
			}
		}
		return []string{*target}
	}

	// Check config
	if cfg != nil && len(cfg.Targets) > 0 {
		return cfg.Targets
	}

	return nil
}

func checkRequiredTools() bool {
	if *probeFlag && !scanner.CheckHttpxInstalled() {
		logger.Fatal("httpx required. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
		return false
	}
	if *subfinderFlag && !discovery.CheckToolInstalled("subfinder") {
		logger.Fatal("subfinder required. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
		return false
	}
	if *alterxFlag && !scanner.CheckAlterxInstalled() {
		logger.Fatal("alterx required. Install: go install github.com/projectdiscovery/alterx/cmd/alterx@latest")
		return false
	}
	if *alterxFlag && !scanner.CheckDnsxInstalled() {
		logger.Fatal("dnsx required. Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
		return false
	}
	if *portsFlag != "" && !scanner.CheckNaabuInstalled() {
		logger.Fatal("naabu required. Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
		return false
	}
	return true
}

func printBanner() {
	cyan := lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	banner := `
░█▀▀░█░█░█▀▄░█▀▀░█░░░█▀█░█░█░
░▀▀█░█░█░█▀▄░█▀▀░█░░░█░█░█▄█░
░▀▀▀░▀▀▀░▀▀░░▀░░░▀▀▀░▀▀▀░▀░▀░
`
	fmt.Println(cyan.Render(banner))
	fmt.Println(dim.Render("subdomain discovery & monitoring pipeline"))
	fmt.Println()
}

func displayHelp() {
	printBanner()

	fmt.Println(" Usage:")
	fmt.Println("   subflow -target example.com")
	fmt.Println("   subflow -target example.com -probe -bypass")
	fmt.Println("   subflow -target example.com -full -notify discord")
	fmt.Println("   subflow -target targets.txt -full -threads 5 -output results.json")
	fmt.Println()

	fmt.Println(" Target:")
	fmt.Println("   -target       target domain, file, or stdin")
	fmt.Println("   -config       config file path")
	fmt.Println()

	fmt.Println(" Discovery:")
	fmt.Println("   -subfinder    use subfinder")
	fmt.Println("   -alterx       use alterx permutations")
	fmt.Println("   -wordlist     wordlist file for alterx (default: subdomains-10000.txt)")
	fmt.Println()

	fmt.Println(" Scanning:")
	fmt.Println("   -probe        HTTP probe with httpx")
	fmt.Println("   -ports        port scan (e.g. \"80,443,8080\")")
	fmt.Println("   -full         full pipeline (all tools)")
	fmt.Println()

	fmt.Println(" HTTP Options:")
	fmt.Println("   -bypass       use 403/404 bypass headers (X-Forwarded-For, etc.)")
	fmt.Println("   -headers      custom headers (e.g. \"Auth:token,X-API:key\")")
	fmt.Println("   -timeout      HTTP timeout in seconds (default: 10)")
	fmt.Println("   -rate-limit   requests per second (0=unlimited)")
	fmt.Println()

	fmt.Println(" Monitoring:")
	fmt.Println("   -monitor      continuous monitoring")
	fmt.Println("   -watch        detect changes (with smart thresholds)")
	fmt.Println("   -interval     poll interval in minutes (default: 30)")
	fmt.Println()

	fmt.Println(" Output:")
	fmt.Println("   -output       output file path")
	fmt.Println("   -format       txt, json, csv (default: txt)")
	fmt.Println("   -silent       silent mode (domains only)")
	fmt.Println()

	fmt.Println(" Processing:")
	fmt.Println("   -threads      parallel target processing")
	fmt.Println("   -resume       resume interrupted scan")
	fmt.Println()

	fmt.Println(" Notifications:")
	fmt.Println("   -notify       discord, telegram, both")
	fmt.Println("   -db           database path")
	fmt.Println()

	fmt.Println(" Severity Alerts (with -watch):")
	fmt.Println("   🔴 CRITICAL   403→200, 401→200 (potential auth bypass)")
	fmt.Println("   🟠 HIGH       404→200 (new endpoint), 200→404 (removed)")
	fmt.Println("   🟠 HIGH       Any→500 (server error), >80% content change")
	fmt.Println("   🟡 MEDIUM     50-80% content change, title change")
	fmt.Println()

	fmt.Println(" Bypass Headers (with -bypass):")
	fmt.Println("   X-Forwarded-For, X-Real-IP, X-Original-URL, X-Rewrite-URL")
	fmt.Println("   X-Client-IP, X-Custom-IP-Authorization, and 15+ more")
	fmt.Println()

	fmt.Println(" Other:")
	fmt.Println("   -version      show version")
	fmt.Println("   -h, -help     show help")
	fmt.Println()
}

