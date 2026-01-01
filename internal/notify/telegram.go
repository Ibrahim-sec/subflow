package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	telegramToken  string
	telegramChatID string
)

// InitTelegram initializes the Telegram notifier
func InitTelegram(token, chatID string) {
	telegramToken = token
	telegramChatID = chatID
}

// SendTelegram sends a notification to Telegram
func SendTelegram(target string, domains []string) {
	if telegramToken == "" || telegramChatID == "" {
		return
	}

	text := BuildTelegramMessage(target, domains)
	SendTelegramMessage(text)
}

// BuildTelegramMessage builds a Telegram message
func BuildTelegramMessage(target string, domains []string) string {
	domainList := strings.Join(domains, "\n")
	return fmt.Sprintf("🔍 *%s* [%d]\n```%s```", target, len(domains), domainList)
}

// SendTelegramMessage sends a message to Telegram
func SendTelegramMessage(text string) {
	if telegramToken == "" || telegramChatID == "" {
		return
	}

	payload := map[string]interface{}{
		"chat_id":                  telegramChatID,
		"text":                     text,
		"parse_mode":               "Markdown",
		"disable_web_page_preview": true,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramToken)

	for attempt := 0; attempt < 3; attempt++ {
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			return
		}

		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			time.Sleep(2 * time.Second * time.Duration(attempt+1))
			continue
		}

		resp.Body.Close()
		return
	}
}

