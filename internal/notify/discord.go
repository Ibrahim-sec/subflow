package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	batchDelay    = 5 * time.Second
	maxBatchSize  = 25
	rateLimitWait = 2 * time.Second
	maxRetries    = 3
)

// Colors for Discord embeds
const (
	ColorGreen  = 3066993  // New domain
	ColorBlue   = 2829617  // Default/batch
	ColorOrange = 15105570 // Change detected
	ColorRed    = 15158332 // Error/down
)

type notificationBuffer struct {
	mu         sync.Mutex
	pending    map[string][]string
	timers     map[string]*time.Timer
	webhookURL string
	bufferType string // "domain" or "livehost"
}

type changeNotification struct {
	Domain      string
	URL         string
	ChangeType  string
	Severity    string
	Description string
	OldValue    string
	NewValue    string
	StatusCode  int
	ContentLen  int64
}

type liveHostNotification struct {
	Domain        string
	URL           string
	StatusCode    int
	ContentLength int64
	Title         string
}

type changeBuffer struct {
	mu         sync.Mutex
	pending    map[string][]changeNotification
	timers     map[string]*time.Timer
	webhookURL string
}

var discordBuffer *notificationBuffer
var changeBufferInstance *changeBuffer
var liveHostBuffer *notificationBuffer

// InitDiscord initializes the Discord notifier
func InitDiscord(webhookURL string) {
	discordBuffer = &notificationBuffer{
		pending:    make(map[string][]string),
		timers:     make(map[string]*time.Timer),
		webhookURL: webhookURL,
		bufferType: "domain",
	}
	changeBufferInstance = &changeBuffer{
		pending:    make(map[string][]changeNotification),
		timers:     make(map[string]*time.Timer),
		webhookURL: webhookURL,
	}
	// Reuse notificationBuffer for live hosts (same structure as domains)
	liveHostBuffer = &notificationBuffer{
		pending:    make(map[string][]string),
		timers:     make(map[string]*time.Timer),
		webhookURL: webhookURL,
		bufferType: "livehost",
	}
}

// SendDiscord sends a domain to the Discord notification buffer
func SendDiscord(domain, target string) {
	if discordBuffer == nil || discordBuffer.webhookURL == "" {
		return
	}
	discordBuffer.add(target, domain)
}

func (n *notificationBuffer) add(target, domain string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.pending[target] = append(n.pending[target], domain)

	if len(n.pending[target]) >= maxBatchSize {
		domains := n.pending[target]
		delete(n.pending, target)
		if timer, exists := n.timers[target]; exists {
			timer.Stop()
			delete(n.timers, target)
		}
		go n.send(target, domains)
		return
	}

	if _, exists := n.timers[target]; !exists {
		n.timers[target] = time.AfterFunc(batchDelay, func() {
			n.flush(target)
		})
	}
}

func (n *notificationBuffer) flush(target string) {
	n.mu.Lock()
	domains, exists := n.pending[target]
	if !exists || len(domains) == 0 {
		n.mu.Unlock()
		return
	}
	delete(n.pending, target)
	delete(n.timers, target)
	n.mu.Unlock()

	n.send(target, domains)
}

func (n *notificationBuffer) send(target string, domains []string) {
	var payload map[string]interface{}
	
	// Check buffer type to determine which payload format to use
	if n.bufferType == "livehost" {
		payload = BuildLiveHostPayload(target, domains)
	} else {
		payload = BuildDiscordPayload(target, domains)
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return
	}

	SendDiscordWebhook(n.webhookURL, jsonData)
}

// BuildDiscordPayload builds a Discord embed payload
func BuildDiscordPayload(target string, domains []string) map[string]interface{} {
	domainList := strings.Join(domains, "\n")

	return map[string]interface{}{
		"tts": false,
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("🔍 %s  [%d]", target, len(domains)),
				"description": fmt.Sprintf("```\n%s\n```", domainList),
				"color":       ColorBlue,
				"timestamp":   time.Now().Format(time.RFC3339),
			},
		},
	}
}

// SendDiscordWebhook sends a raw payload to Discord
func SendDiscordWebhook(webhookURL string, jsonData []byte) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			return
		}

		switch resp.StatusCode {
		case http.StatusOK, http.StatusNoContent:
			resp.Body.Close()
			return
		case http.StatusTooManyRequests:
			resp.Body.Close()
			time.Sleep(rateLimitWait * time.Duration(attempt+1))
			continue
		default:
			resp.Body.Close()
			return
		}
	}
}

// Truncate truncates a string to maxLen
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
		return s[:maxLen] + "..."
}

// SendLiveHost buffers a live host notification for batching
func SendLiveHost(domain, url string, statusCode int, contentLength int64, title, target string) {
	if liveHostBuffer == nil || liveHostBuffer.webhookURL == "" {
		return
	}

	// Format: domain:port | status | size | title
	formatted := fmt.Sprintf("%s | Status: %d | Size: %d | Title: %s", url, statusCode, contentLength, Truncate(title, 50))
	liveHostBuffer.add(target, formatted)
}

// BuildLiveHostPayload builds a Discord embed payload for batched live hosts
func BuildLiveHostPayload(target string, hosts []string) map[string]interface{} {
	hostList := strings.Join(hosts, "\n")

	// Truncate if too long (Discord limit is 4096 chars)
	if len(hostList) > 4000 {
		hostList = hostList[:4000] + "\n\n... (truncated)"
	}

	return map[string]interface{}{
		"tts": false,
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("🎯 Live Hosts: %s  [%d]", target, len(hosts)),
				"description": fmt.Sprintf("```\n%s\n```", hostList),
				"color":       ColorGreen,
				"timestamp":     time.Now().Format(time.RFC3339),
			},
		},
	}
}

// SendChangeNotification buffers a change notification for batching
func SendChangeNotification(domain, url, changeType, severity, description, oldValue, newValue string, statusCode int, contentLen int64, target string) {
	if changeBufferInstance == nil || changeBufferInstance.webhookURL == "" {
		return
	}

	change := changeNotification{
		Domain:      domain,
		URL:         url,
		ChangeType:  changeType,
		Severity:    severity,
		Description: description,
		OldValue:    oldValue,
		NewValue:    newValue,
		StatusCode:  statusCode,
		ContentLen:  contentLen,
	}

	changeBufferInstance.add(target, change)
}

func (c *changeBuffer) add(target string, change changeNotification) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pending[target] = append(c.pending[target], change)

	if len(c.pending[target]) >= maxBatchSize {
		changes := c.pending[target]
		delete(c.pending, target)
		if timer, exists := c.timers[target]; exists {
			timer.Stop()
			delete(c.timers, target)
		}
		go c.send(target, changes)
		return
	}

	if _, exists := c.timers[target]; !exists {
		c.timers[target] = time.AfterFunc(batchDelay, func() {
			c.flush(target)
		})
	}
}

func (c *changeBuffer) flush(target string) {
	c.mu.Lock()
	changes, exists := c.pending[target]
	if !exists || len(changes) == 0 {
		c.mu.Unlock()
		return
	}
	delete(c.pending, target)
	delete(c.timers, target)
	c.mu.Unlock()

	c.send(target, changes)
}

func (c *changeBuffer) send(target string, changes []changeNotification) {
	payload := BuildChangePayload(target, changes)

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return
	}

	SendDiscordWebhook(c.webhookURL, jsonData)
}

// BuildChangePayload builds a Discord embed payload for batched changes
func BuildChangePayload(target string, changes []changeNotification) map[string]interface{} {
	// Group by severity for better organization
	critical := []changeNotification{}
	high := []changeNotification{}
	medium := []changeNotification{}
	low := []changeNotification{}

	for _, change := range changes {
		switch change.Severity {
		case "critical":
			critical = append(critical, change)
		case "high":
			high = append(high, change)
		case "medium":
			medium = append(medium, change)
		default:
			low = append(low, change)
		}
	}

	var embeds []map[string]interface{}
	totalChanges := len(changes)

	// Build description with all changes
	var description strings.Builder
	description.WriteString(fmt.Sprintf("**%d change(s) detected**\n\n", totalChanges))

	// Add critical changes
	if len(critical) > 0 {
		description.WriteString(fmt.Sprintf("🔴 **CRITICAL (%d):**\n", len(critical)))
		for _, change := range critical {
			description.WriteString(fmt.Sprintf("• `%s` - %s\n", change.Domain, change.Description))
		}
		description.WriteString("\n")
	}

	// Add high priority changes
	if len(high) > 0 {
		description.WriteString(fmt.Sprintf("🟠 **HIGH (%d):**\n", len(high)))
		for _, change := range high {
			description.WriteString(fmt.Sprintf("• `%s` - %s\n", change.Domain, change.Description))
		}
		description.WriteString("\n")
	}

	// Add medium priority changes
	if len(medium) > 0 {
		description.WriteString(fmt.Sprintf("🟡 **MEDIUM (%d):**\n", len(medium)))
		for _, change := range medium {
			description.WriteString(fmt.Sprintf("• `%s` - %s\n", change.Domain, change.Description))
		}
		description.WriteString("\n")
	}

	// Add low priority changes (if any)
	if len(low) > 0 {
		description.WriteString(fmt.Sprintf("🟢 **LOW (%d):**\n", len(low)))
		for _, change := range low {
			description.WriteString(fmt.Sprintf("• `%s` - %s\n", change.Domain, change.Description))
		}
	}

	// Determine color based on highest severity
	var color int
	var title string
	if len(critical) > 0 {
		color = ColorRed
		title = fmt.Sprintf("🔴 CRITICAL Changes: %s [%d]", target, totalChanges)
	} else if len(high) > 0 {
		color = ColorOrange
		title = fmt.Sprintf("🟠 Changes Detected: %s [%d]", target, totalChanges)
	} else if len(medium) > 0 {
		color = 16776960 // Yellow
		title = fmt.Sprintf("🟡 Changes Detected: %s [%d]", target, totalChanges)
	} else {
		color = 3066993 // Green
		title = fmt.Sprintf("🟢 Changes Detected: %s [%d]", target, totalChanges)
	}

	// Truncate description if too long (Discord limit is 4096 chars)
	desc := description.String()
	if len(desc) > 4000 {
		desc = desc[:4000] + "\n\n... (truncated)"
	}

	embeds = append(embeds, map[string]interface{}{
		"title":       title,
		"description": fmt.Sprintf("```\n%s\n```", desc),
		"color":       color,
		"timestamp":   time.Now().Format(time.RFC3339),
		"footer":      map[string]string{"text": fmt.Sprintf("Target: %s", target)},
	})

	return map[string]interface{}{
		"tts":    false,
		"embeds": embeds,
	}
}

