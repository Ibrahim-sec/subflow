package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	db     *sql.DB
	dbOnce sync.Once
	dbMu   sync.Mutex
)

// CustomDBPath allows overriding the default database path
var CustomDBPath string

// InitDB initializes the SQLite database
func InitDB() error {
	var initErr error
	dbOnce.Do(func() {
		dbPath := GetDBPath()

		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			initErr = err
			return
		}

		var err error
		db, err = sql.Open("sqlite3", dbPath+"?_busy_timeout=5000&_journal_mode=WAL")
		if err != nil {
			initErr = err
			return
		}

		schema := `
		CREATE TABLE IF NOT EXISTS domains (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT UNIQUE NOT NULL,
			target TEXT NOT NULL,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS probe_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL,
			url TEXT,
			status_code INTEGER,
			content_length INTEGER,
			title TEXT,
			server TEXT,
			technologies TEXT,
			response_time_ms INTEGER,
			error TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (domain) REFERENCES domains(domain)
		);

		CREATE TABLE IF NOT EXISTS scan_state (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			phase TEXT NOT NULL,
			domains_processed INTEGER DEFAULT 0,
			last_domain TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
		CREATE INDEX IF NOT EXISTS idx_domains_target ON domains(target);
		CREATE INDEX IF NOT EXISTS idx_probe_results_domain ON probe_results(domain);
		CREATE INDEX IF NOT EXISTS idx_probe_results_timestamp ON probe_results(timestamp);
		CREATE INDEX IF NOT EXISTS idx_scan_state_target ON scan_state(target);
		`

		if _, err := db.Exec(schema); err != nil {
			initErr = err
			return
		}
	})
	return initErr
}

// GetDBPath returns the path to the SQLite database
func GetDBPath() string {
	if CustomDBPath != "" {
		return CustomDBPath
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "subflow.db"
	}
	return filepath.Join(home, ".config", "subflow", "subflow.db")
}

// IsNewDomain checks if a domain has been seen before
func IsNewDomain(domain string) bool {
	if db == nil {
		if err := InitDB(); err != nil {
			return true
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM domains WHERE domain = ?", domain).Scan(&count)
	if err != nil {
		return true
	}

	if count == 0 {
		_, err = db.Exec(
			"INSERT INTO domains (domain, target) VALUES (?, ?)",
			domain, "",
		)
		return true
	}

	_, _ = db.Exec("UPDATE domains SET last_seen = CURRENT_TIMESTAMP WHERE domain = ?", domain)
	return false
}

// StoreProbeResult stores a probe result in the database
func StoreProbeResult(domain, url string, statusCode int, contentLength int64, title, server, technologies string, responseTimeMs int64, probeError string) error {
	if db == nil {
		if err := InitDB(); err != nil {
			return err
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec(`
		INSERT INTO probe_results (domain, url, status_code, content_length, title, server, technologies, response_time_ms, error, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		domain,
		url,
		statusCode,
		contentLength,
		title,
		server,
		technologies,
		responseTimeMs,
		probeError,
		time.Now(),
	)

	return err
}

// GetLastProbeResult retrieves the most recent probe result for a domain
func GetLastProbeResult(domain string) (statusCode int, contentLength int64, title string, found bool) {
	if db == nil {
		if err := InitDB(); err != nil {
			return 0, 0, "", false
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	row := db.QueryRow(`
		SELECT status_code, content_length, title
		FROM probe_results
		WHERE domain = ?
		ORDER BY timestamp DESC
		LIMIT 1 OFFSET 1
	`, domain)

	err := row.Scan(&statusCode, &contentLength, &title)
	if err == sql.ErrNoRows {
		return 0, 0, "", false
	}
	if err != nil {
		return 0, 0, "", false
	}

	return statusCode, contentLength, title, true
}

// GetAllKnownDomains returns all known domains for a target
func GetAllKnownDomains(target string) []string {
	if db == nil {
		if err := InitDB(); err != nil {
			return nil
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	rows, err := db.Query("SELECT domain FROM domains WHERE target = ? OR target = ''", target)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err == nil {
			domains = append(domains, domain)
		}
	}

	return domains
}

// SaveScanState saves the current scan progress
func SaveScanState(target, phase string, domainsProcessed int, lastDomain string) error {
	if db == nil {
		if err := InitDB(); err != nil {
			return err
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec(`
		INSERT OR REPLACE INTO scan_state (target, phase, domains_processed, last_domain, updated_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, target, phase, domainsProcessed, lastDomain)

	return err
}

// GetScanState retrieves the saved scan state for a target
func GetScanState(target string) (phase string, domainsProcessed int, lastDomain string, found bool) {
	if db == nil {
		if err := InitDB(); err != nil {
			return "", 0, "", false
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	row := db.QueryRow(`
		SELECT phase, domains_processed, last_domain
		FROM scan_state
		WHERE target = ?
		ORDER BY updated_at DESC
		LIMIT 1
	`, target)

	err := row.Scan(&phase, &domainsProcessed, &lastDomain)
	if err == sql.ErrNoRows {
		return "", 0, "", false
	}
	if err != nil {
		return "", 0, "", false
	}

	return phase, domainsProcessed, lastDomain, true
}

// ClearScanState clears the scan state for a target
func ClearScanState(target string) error {
	if db == nil {
		return nil
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec("DELETE FROM scan_state WHERE target = ?", target)
	return err
}

// Close closes the database connection
func Close() {
	if db != nil {
		db.Close()
	}
}

