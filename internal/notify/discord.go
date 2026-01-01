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
}

var discordBuffer *notificationBuffer

// InitDiscord initializes the Discord notifier
func InitDiscord(webhookURL string) {
	discordBuffer = &notificationBuffer{
		pending:    make(map[string][]string),
		timers:     make(map[string]*time.Timer),
		webhookURL: webhookURL,
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
	payload := BuildDiscordPayload(target, domains)

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

