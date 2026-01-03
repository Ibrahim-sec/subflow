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
	threadsFlag = flag.Int("threads", 5, "parallel target processing (default: 5)")
	resumeFlag  = flag.Bool("resume", false, "resume interrupted scan")
	notifyOnlyChanges = flag.Bool("notify-only-changes", false, "only notify on subsequent runs (skip first-run notifications)")

	// HTTP probing flags
	headersFlag   = flag.String("headers", "", "custom headers (comma-separated: 'H1:V1,H2:V2')")
	bypassFlag    = flag.Bool("bypass", false, "use 403/404 bypass headers")
	rateLimitFlag = flag.Int("rate-limit", 0, "requests per second (0=unlimited)")
	timeoutFlag   = flag.Int("timeout", 10, "HTTP timeout in seconds")

	// Storage and notification
	dbPath       = flag.String("db", "", "database path")
	notifyOption = flag.String("notify", "", "discord, telegram, both")
	disableNotify = flag.Bool("no-notify", false, "disable all notifications (Discord/Telegram)")

	// Other flags
	showVersion = flag.Bool("version", false, "show version")
	showHelp    = flag.Bool("h", false, "show help")
	showHelp2   = flag.Bool("help", false, "show help")
	testNotify  = flag.Bool("test-notify", false, "test Discord/Telegram notification")
	clearDB     = flag.Bool("clear-db", false, "delete all domains and probe results from database")
	clearTarget = flag.String("clear-target", "", "delete all domains for a specific target")
	dbStats     = flag.Bool("db-stats", false, "show database statistics")

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

	// Handle test notification
	if *testNotify {
		testNotification()
		return
	}

	// Handle database cleanup
	if *clearDB {
		clearDatabase()
		return
	}

	if *clearTarget != "" {
		clearTargetDatabase(*clearTarget)
		return
	}

	if *dbStats {
		showDatabaseStats()
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

	// Check if this is a first run (no existing domains for this target)
	isFirstRun := isFirstRunForTarget(target)

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
		notifyNewDomains(newDiscoveryDomains, target, "discovery", isFirstRun)
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

			// Only use the base domain for alterx, not all discovered subdomains
			// This prevents exponential permutation growth
			baseDomainInput := []string{target}
			permutations = scanner.RunAlterxParallel(baseDomainInput, smartPatterns)
			
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
			// Only use the base domain for alterx, not all discovered subdomains
			baseDomainInput := []string{target}
			permutations = scanner.RunAlterxParallel(baseDomainInput, defaultPatterns)
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
			notifyNewDomains(newAlterxDomains, target, "alterx", isFirstRun)
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
				sendProbeNotification(r, target, isFirstRun)
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
func notifyNewDomains(domains []string, target, stage string, isFirstRun bool) {
	if len(domains) == 0 {
		return
	}

	// Skip all notifications if -no-notify is set
	if *disableNotify {
		if !*silentFlag {
			logger.Debug("notifications disabled", "stage", stage, "count", len(domains))
		}
		return
	}

	// Skip notifications on first run if -notify-only-changes is set
	if *notifyOnlyChanges && isFirstRun {
		if !*silentFlag {
			logger.Debug("skipping first-run notifications", "stage", stage, "count", len(domains), "reason", "-notify-only-changes enabled")
		}
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

// isFirstRunForTarget checks if this is the first time scanning this target
func isFirstRunForTarget(target string) bool {
	knownDomains := store.GetAllKnownDomains(target)
	return len(knownDomains) == 0
}

// sendProbeNotification sends detailed notification for a probed domain
func sendProbeNotification(result scanner.ProbeResult, target string, isFirstRun bool) {
	// Skip all notifications if -no-notify is set
	if *disableNotify {
		return
	}

	if webhookURL == "" && !telegramEnabled {
		return
	}

	// Skip notifications on first run if -notify-only-changes is set
	if *notifyOnlyChanges && isFirstRun {
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

// clearDatabase deletes all domains and probe results from the database
func clearDatabase() {
	fmt.Println("🗑️  Clearing all domains and probe results from database...")

	// Get stats before deletion
	domainCount, probeCount, _, err := store.GetDatabaseStats()
	if err != nil {
		fmt.Printf("❌ Failed to get database stats: %v\n", err)
		return
	}

	if domainCount == 0 && probeCount == 0 {
		fmt.Println("✅ Database is already empty")
		return
	}

	fmt.Printf("   Found: %d domains, %d probe results\n", domainCount, probeCount)
	fmt.Print("   Are you sure you want to delete all data? (yes/no): ")

	var confirmation string
	fmt.Scanln(&confirmation)
	if confirmation != "yes" && confirmation != "y" {
		fmt.Println("❌ Cancelled")
		return
	}

	err = store.ClearAllDomains()
	if err != nil {
		fmt.Printf("❌ Failed to clear database: %v\n", err)
		return
	}

	// Also clear scan state
	store.ClearAllScanState()

	fmt.Printf("✅ Successfully deleted %d domains and %d probe results\n", domainCount, probeCount)
	fmt.Println("   Database location:", store.GetDBPath())
}

// clearTargetDatabase deletes all domains for a specific target
func clearTargetDatabase(target string) {
	fmt.Printf("🗑️  Clearing all domains for target: %s\n", target)

	// Get stats before deletion
	domainCount, _, _, err := store.GetDatabaseStats()
	if err != nil {
		fmt.Printf("❌ Failed to get database stats: %v\n", err)
		return
	}

	if domainCount == 0 {
		fmt.Println("✅ Database is empty")
		return
	}

	fmt.Print("   Are you sure you want to delete all data for this target? (yes/no): ")

	var confirmation string
	fmt.Scanln(&confirmation)
	if confirmation != "yes" && confirmation != "y" {
		fmt.Println("❌ Cancelled")
		return
	}

	err = store.ClearTargetDomains(target)
	if err != nil {
		fmt.Printf("❌ Failed to clear target data: %v\n", err)
		return
	}

	// Clear scan state for this target
	store.ClearScanState(target)

	fmt.Printf("✅ Successfully deleted all domains for target: %s\n", target)
	fmt.Println("   Database location:", store.GetDBPath())
}

// showDatabaseStats displays database statistics
func showDatabaseStats() {
	fmt.Println("📊 Database Statistics")
	fmt.Println("   Location:", store.GetDBPath())

	domainCount, probeCount, scanStateCount, err := store.GetDatabaseStats()
	if err != nil {
		fmt.Printf("❌ Failed to get database stats: %v\n", err)
		return
	}

	fmt.Printf("   Domains: %d\n", domainCount)
	fmt.Printf("   Probe Results: %d\n", probeCount)
	fmt.Printf("   Scan States: %d\n", scanStateCount)

	if domainCount > 0 {
		dbSize := getDatabaseSize()
		if dbSize > 0 {
			fmt.Printf("   Database Size: %s\n", formatBytes(dbSize))
		}
	}
}

// getDatabaseSize returns the size of the database file
func getDatabaseSize() int64 {
	dbPath := store.GetDBPath()
	info, err := os.Stat(dbPath)
	if err != nil {
		return 0
	}
	return info.Size()
}

// formatBytes formats bytes into human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// testNotification sends a test notification to verify webhook configuration
func testNotification() {
	fmt.Println("🔔 Testing notification configuration...")

	// Load config
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		fmt.Println("   Create config with: subflow -target example.com (first run creates template)")
		return
	}

	if cfg == nil {
		fmt.Println("❌ No config file found")
		fmt.Println("   Config location: ~/.config/subflow/config.yaml")
		fmt.Println("   Create config with: subflow -target example.com (first run creates template)")
		return
	}

	webhookURL := strings.TrimSpace(cfg.Webhook)
	hasTelegram := cfg.TelegramBotToken != "" && cfg.TelegramChatID != ""

	if webhookURL == "" && !hasTelegram {
		fmt.Println("❌ No notification channels configured")
		fmt.Println("   Edit ~/.config/subflow/config.yaml and add:")
		fmt.Println("   webhook: \"https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN\"")
		return
	}

	// Test Discord
	if webhookURL != "" {
		fmt.Printf("📤 Sending test to Discord webhook...\n")
		
		payload := map[string]interface{}{
			"embeds": []map[string]interface{}{
				{
					"title":       "🧪 Subflow Test Notification",
					"description": "If you see this message, your Discord webhook is configured correctly!",
					"color":       3066993, // Green
					"fields": []map[string]interface{}{
						{"name": "Status", "value": "✅ Working", "inline": true},
						{"name": "Version", "value": version, "inline": true},
					},
					"footer":    map[string]string{"text": "subflow notification test"},
					"timestamp": time.Now().Format(time.RFC3339),
				},
			},
		}

		jsonData, _ := json.Marshal(payload)
		notify.SendDiscordWebhook(webhookURL, jsonData)
		fmt.Println("✅ Discord test sent! Check your Discord channel.")
	}

	// Test Telegram
	if hasTelegram {
		fmt.Printf("📤 Sending test to Telegram...\n")
		notify.InitTelegram(cfg.TelegramBotToken, cfg.TelegramChatID)
		notify.SendTelegramMessage("🧪 *Subflow Test Notification*\n\nIf you see this message, your Telegram bot is configured correctly!\n\n✅ Status: Working\n📦 Version: " + version)
		fmt.Println("✅ Telegram test sent! Check your Telegram chat.")
	}

	fmt.Println("\n📋 Notification settings:")
	if webhookURL != "" {
		// Mask the webhook URL for security
		masked := webhookURL
		if len(webhookURL) > 50 {
			masked = webhookURL[:40] + "..." + webhookURL[len(webhookURL)-10:]
		}
		fmt.Printf("   Discord: %s\n", masked)
	} else {
		fmt.Println("   Discord: not configured")
	}
	if hasTelegram {
		fmt.Printf("   Telegram: bot configured (chat: %s)\n", cfg.TelegramChatID)
	} else {
		fmt.Println("   Telegram: not configured")
	}
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
		logger.Info("monitoring mode", "interval", interval, "targets", len(targets))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !*silentFlag {
				logger.Info("monitoring cycle", "targets", len(targets))
			}

			// Use parallel processing for monitoring too
			threads := *threadsFlag
			if threads < 1 {
				threads = 5 // Default to 5 if not set
			}

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

					// Run discovery pipeline
					runTargetPipeline(ctx, t, cfg, outputWriter)

					if *watchFlag {
						// Re-probe existing domains in chunks to avoid memory issues
						probeExistingDomainsInChunks(ctx, t)
					}
				}(target)
			}

			wg.Wait()

			if !*silentFlag {
				logger.Info("monitoring cycle complete", "next_cycle", interval)
			}
		}
	}
}

// probeExistingDomainsInChunks probes existing domains in chunks to avoid memory exhaustion
func probeExistingDomainsInChunks(ctx context.Context, target string) {
	if !scanner.CheckHttpxInstalled() {
		return
	}

	// Get domains in chunks to avoid loading 500k+ domains into memory
	const chunkSize = 1000 // Process 1000 domains at a time
	offset := 0
	totalProbed := 0

	for {
		select {
		case <-ctx.Done():
			if !*silentFlag {
				logger.Debug("watch probing cancelled", "target", target, "probed", totalProbed)
			}
			return
		default:
		}

		domains := store.GetKnownDomainsChunk(target, chunkSize, offset)
		if len(domains) == 0 {
			break // No more domains
		}

		if !*silentFlag {
			logger.Debug("probing domain chunk", "target", target, "chunk_size", len(domains), "offset", offset)
		}

		results := scanner.WildcardAwareProbe(domains, target)

		for _, r := range results {
			checkForChanges(r, target)
		}

		totalProbed += len(domains)
		offset += chunkSize

		// Small delay between chunks to avoid overwhelming the system
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}

	if !*silentFlag && totalProbed > 0 {
		logger.Debug("watch probing complete", "target", target, "total_probed", totalProbed)
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
	// Skip all notifications if -no-notify is set
	if *disableNotify {
		return
	}

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
	fmt.Println("   subflow -test-notify                      # test Discord/Telegram webhook")
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
	fmt.Println("   -notify              discord, telegram, both")
	fmt.Println("   -no-notify            disable all notifications (Discord/Telegram)")
	fmt.Println("   -test-notify         test Discord/Telegram webhook")
	fmt.Println("   -notify-only-changes only notify on subsequent runs (skip first-run)")
	fmt.Println()
	fmt.Println(" Database:")
	fmt.Println("   -db                  database path")
	fmt.Println("   -clear-db            delete all domains and probe results")
	fmt.Println("   -clear-target        delete all domains for a specific target")
	fmt.Println("   -db-stats            show database statistics")
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

