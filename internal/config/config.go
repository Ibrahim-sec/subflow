package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the subflow configuration
type Config struct {
	// Notification settings
	Webhook          string `yaml:"webhook"`
	TelegramBotToken string `yaml:"telegram_bot_token"`
	TelegramChatID   string `yaml:"telegram_chat_id"`

	// Targets
	Targets []string `yaml:"targets"`

	// Tool settings
	Tools ToolsConfig `yaml:"tools,omitempty"`
}

// ToolsConfig holds settings for external tools
type ToolsConfig struct {
	Ports          string   `yaml:"ports,omitempty"`
	ExtendedPorts  string   `yaml:"extended_ports,omitempty"`
	AlterxPatterns []string `yaml:"alterx_patterns,omitempty"`
	AlterxWordlist string   `yaml:"alterx_wordlist,omitempty"`
	HttpxTimeout   int      `yaml:"httpx_timeout,omitempty"`
	HttpxThreads   int      `yaml:"httpx_threads,omitempty"`
	SubfinderAll   bool     `yaml:"subfinder_all,omitempty"`
}

var customConfigPath string

func SetConfigPath(path string) {
	customConfigPath = path
}

func GetConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "subflow"), nil
}

func GetConfigPath() (string, error) {
	if customConfigPath != "" {
		return customConfigPath, nil
	}
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

func CreateConfigTemplate() error {
	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	template := `# subflow configuration
# subdomain discovery and monitoring tool

# ========== Notification Settings ==========

# Discord webhook URL for notifications
webhook: ""

# Telegram bot credentials (optional)
telegram_bot_token: ""
telegram_chat_id: ""

# ========== Targets ==========

# Target domains to monitor (can also use -target flag)
targets:
  # - example.com
  # - target.com

# ========== Tool Settings (Optional) ==========

tools:
  # Default ports for naabu scanning
  ports: "80,443,8080,8443,8000,8888,9000,9443"

  # Extended ports for thorough scanning
  extended_ports: "80,443,8080,8443,8000-8100,9000-9100"

  # httpx settings
  httpx_timeout: 10
  httpx_threads: 50

  # subfinder: use -all flag for more sources
  subfinder_all: true
`

	return os.WriteFile(configPath, []byte(template), 0644)
}

func Load() (*Config, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func Exists() bool {
	configPath, err := GetConfigPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(configPath)
	return err == nil
}

func Validate(cfg *Config) error {
	if cfg.Webhook == "" || cfg.Webhook == `""` {
		return fmt.Errorf("webhook not configured")
	}
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("no targets configured")
	}
	return nil
}

// DefaultPorts returns the default ports for scanning
func DefaultPorts() string {
	return "80,443,8080,8443,8000,8888,9000,9443"
}

// ExtendedPorts returns extended ports for thorough scanning
func ExtendedPorts() string {
	return "80,443,1090,1098,1099,4444,4445,4786,4848,5555,5556,7000-7100,8000-8100,8443,8686,9000-9100,9012,9443,9503,10000,10999,11099,11111,45000,45001,47001,47002,50500"
}

