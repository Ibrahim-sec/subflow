<p align="center">
  <h1 align="center">⚡ subflow</h1>
  <p align="center">Automated subdomain enumeration & probing pipeline</p>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#pipeline">Pipeline</a> •
  <a href="#configuration">Configuration</a>
</p>

---

> **subflow** is an all-in-one subdomain discovery and probing tool that chains together the best ProjectDiscovery tools into a seamless automated pipeline.

## Features

- 🔍 **Multi-source enumeration** via subfinder
- 🧬 **Smart wordlist generation** using alterx with auto-detected patterns
- ✅ **DNS resolution & validation** with dnsx
- 🔌 **Port scanning** using naabu
- 🌐 **HTTP probing** with httpx
- 💾 **SQLite database** for persistent storage & deduplication
- 📢 **Real-time notifications** (Discord & Telegram)
- 🔄 **Continuous monitoring** mode
- 📊 **Multiple output formats** (JSON, plain text)

## Installation

```bash
go install github.com/ibrahim-sec/subflow/cmd/subflow@latest
```

### Required Tools

subflow requires the following ProjectDiscovery tools:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Usage

### Basic Examples

```bash
# Full pipeline (easiest way)
subflow -target example.com -full

# Single target with subfinder only
subflow -target example.com -subfinder

# Manual pipeline: enumerate → mutate → resolve → probe
subflow -target example.com -subfinder -alterx -probe

# Multiple targets from file
subflow -targets targets.txt -subfinder -alterx -probe

# Pipe targets via stdin
cat domains.txt | subflow -stdin -subfinder -probe

# With port scanning
subflow -target example.com -subfinder -probe -ports "80,443,8080,8443"

# Custom output
subflow -target example.com -subfinder -probe -output results.json -format json

# Process 5 targets in parallel (faster for multiple targets)
subflow -target targets.txt -full -threads 5

# Skip notifications on first run (only notify on subsequent discoveries)
subflow -target example.com -full -notify-only-changes

# Disable all notifications temporarily (useful for initial scans)
subflow -target example.com -full -no-notify
```

### Flags

```text
TARGET:
   -target string       Single target domain
   -targets string      File containing list of targets
   -stdin               Read targets from stdin

ENUMERATION:
   -subfinder           Run subfinder for subdomain enumeration
   -alterx              Run alterx for wordlist generation (auto-detects patterns)
   -probe               Enable HTTP probing with httpx
   -full                Full pipeline (subfinder + alterx + dnsx + probe)

PORTS:
   -ports string        Ports to scan (e.g., "80,443,8080" or "top-100")

DNS:
   -resolvers string    File containing DNS resolvers
   -wildcard            Filter wildcard DNS responses

OUTPUT:
   -output string       Output file path
   -format string       Output format: text, json (default: text)
   -db string           SQLite database path (default: subflow.db)
   -silent              Suppress banner and info messages
   -verbose             Show verbose output
   -no-color            Disable colored output

NOTIFICATIONS:
   -discord string         Discord webhook URL
   -telegram-token         Telegram bot token
   -telegram-chat          Telegram chat ID
   -notify string          Notification provider: discord, telegram, both
   -no-notify              Disable all notifications (temporary disable)
   -test-notify            Test Discord/Telegram webhook configuration
   -notify-only-changes    Only notify on subsequent runs (skip first-run notifications)

CONFIG:
   -config string          Path to config file
   -threads int            Number of concurrent targets (default: 5)

DATABASE:
   -db string              Database path (default: ~/.config/subflow/subflow.db)
   -clear-db               Delete all domains and probe results from database
   -clear-target string    Delete all domains for a specific target
   -db-stats               Show database statistics
   -timeout int         Timeout in seconds (default: 30)
   -delay int           Delay between requests in ms

OTHER:
   -version             Show version
   -update              Update to latest version
   -h, -help            Show help
```

## Pipeline

subflow chains tools in this order:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  subfinder  │ ──► │   alterx    │ ──► │    dnsx     │ ──► │    naabu    │ ──► │    httpx    │
│ (enumerate) │     │  (mutate)   │     │  (resolve)  │     │   (ports)   │     │   (probe)   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

### Pipeline Stages

| Stage | Tool | Description |
|-------|------|-------------|
| 1 | **subfinder** | Passive subdomain enumeration from multiple sources |
| 2 | **alterx** | Smart wordlist generation with auto-detected patterns |
| 3 | **dnsx** | DNS resolution and wildcard filtering |
| 4 | **naabu** | Fast port scanning (optional) |
| 5 | **httpx** | HTTP probing and technology detection |

### Smart Alterx Patterns

subflow automatically detects patterns from discovered subdomains:

```
Input: api.example.com, dev.example.com, staging.example.com

Auto-detected patterns:
  → {{word}}.example.com
  → {{word}}-{{word}}.example.com
  → {{word}}.{{word}}.example.com
```

## Configuration

### Config File

Create `config.yaml`:

```yaml
# Notifications
discord_webhook: "https://discord.com/api/webhooks/..."
telegram_token: "your-bot-token"
telegram_chat_id: "your-chat-id"

# Settings
threads: 20
timeout: 30
resolvers: "resolvers.txt"

# Default ports
ports: "80,443,8080,8443"
```

### Using Config

```bash
subflow -target example.com -config config.yaml -subfinder -probe
```

### Testing Notifications

Test your Discord/Telegram webhook before running scans:

```bash
subflow -test-notify
```

This sends a test message to verify your notification channels are working correctly.

## Output

### Database

All results are stored in SQLite (`~/.config/subflow/subflow.db`):

```sql
-- View all subdomains
SELECT * FROM domains WHERE target = 'example.com';

-- View HTTP results
SELECT url, status_code, title FROM probe_results;

-- Export to CSV
.mode csv
.output results.csv
SELECT * FROM domains;
```

#### Database Management

```bash
# View database statistics
subflow -db-stats

# Delete all domains and probe results (with confirmation)
subflow -clear-db

# Delete all domains for a specific target
subflow -clear-target example.com
```

### JSON Output

```bash
subflow -target example.com -subfinder -probe -output results.json -format json
```

```json
{
  "subdomain": "api.example.com",
  "ip": "93.184.216.34",
  "ports": [80, 443],
  "http": {
    "url": "https://api.example.com",
    "status": 200,
    "title": "API Documentation"
  }
}
```

## Continuous Monitoring

Run in the background for continuous discovery:

```bash
# Linux/macOS
nohup subflow -target example.com -subfinder -probe > subflow.log 2>&1 &

# With cron (every hour)
0 * * * * /path/to/subflow -target example.com -subfinder -probe >> /var/log/subflow.log 2>&1

# Windows (Task Scheduler or background)
Start-Process -NoNewWindow -FilePath "subflow.exe" -ArgumentList "-target example.com -subfinder -probe"
```

## Tips

> **Performance**: Use `-threads` to increase concurrency for large scopes

> **Rate Limiting**: Add `-delay 100` to avoid triggering WAFs

> **Resolvers**: Use custom resolvers with `-resolvers resolvers.txt` for better results

> **Wildcards**: Enable `-wildcard` to filter out wildcard DNS responses

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Happy Hunting! 🎯</b>
</p>
