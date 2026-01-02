package store

import (
	"database/sql"
	"fmt"
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
		// Optimized connection string for high-performance operations
		// WAL mode: better concurrency, faster writes
		// _cache_size: increase cache (negative = KB, so -256000 = 256MB)
		// _synchronous: NORMAL is faster than FULL, safe with WAL
		// _foreign_keys: can disable for bulk inserts (we'll enable per-connection)
		db, err = sql.Open("sqlite3", dbPath+"?_busy_timeout=10000&_journal_mode=WAL&_cache_size=-256000&_synchronous=NORMAL")
		if err != nil {
			initErr = err
			return
		}

		// Set connection pool settings for high concurrency
		db.SetMaxOpenConns(25) // Allow multiple concurrent connections
		db.SetMaxIdleConns(5)  // Keep some connections warm
		db.SetConnMaxLifetime(time.Hour)

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

		// Performance optimizations for bulk operations
		_, _ = db.Exec("PRAGMA foreign_keys = ON") // Enable foreign keys
		_, _ = db.Exec("PRAGMA temp_store = MEMORY") // Use memory for temp tables
		_, _ = db.Exec("PRAGMA mmap_size = 268435456") // 256MB memory-mapped I/O
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

var dbInitFailed bool
var dbInitError error

// IsNewDomain checks if a domain has been seen before
// Uses INSERT OR IGNORE for better performance with concurrent access
func IsNewDomain(domain string) bool {
	if db == nil {
		if err := InitDB(); err != nil {
			if !dbInitFailed {
				dbInitFailed = true
				dbInitError = err
			}
			return true
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	// Try INSERT OR IGNORE first (faster for new domains)
	result, err := db.Exec(
		"INSERT OR IGNORE INTO domains (domain, target) VALUES (?, ?)",
		domain, "",
	)
	if err != nil {
		return true
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		// New domain inserted
		return true
	}

	// Domain exists, update last_seen
	_, _ = db.Exec("UPDATE domains SET last_seen = CURRENT_TIMESTAMP WHERE domain = ?", domain)
	return false
}

// StoreProbeResult stores a probe result in the database
// Uses prepared statement pattern for better performance
func StoreProbeResult(domain, url string, statusCode int, contentLength int64, title, server, technologies string, responseTimeMs int64, probeError string) error {
	if db == nil {
		if err := InitDB(); err != nil {
			return err
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	// Use INSERT OR REPLACE to handle duplicates gracefully
	_, err := db.Exec(`
		INSERT OR REPLACE INTO probe_results (domain, url, status_code, content_length, title, server, technologies, response_time_ms, error, timestamp)
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

// GetDBStatus returns whether the database is working and any error
func GetDBStatus() (working bool, err error) {
	if dbInitFailed {
		return false, dbInitError
	}
	if db == nil {
		if err := InitDB(); err != nil {
			return false, err
		}
	}
	return true, nil
}

// BatchStoreDomains stores multiple domains in a single transaction (much faster)
func BatchStoreDomains(domains []string, target string) error {
	if db == nil {
		if err := InitDB(); err != nil {
			return err
		}
	}

	if len(domains) == 0 {
		return nil
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	// Use transaction for batch insert (much faster)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO domains (domain, target) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, domain := range domains {
		if _, err := stmt.Exec(domain, target); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ClearAllDomains deletes all domains and related probe results from the database
func ClearAllDomains() error {
	if db == nil {
		if err := InitDB(); err != nil {
			return err
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	// Delete probe_results first (due to foreign key constraint)
	_, err := db.Exec("DELETE FROM probe_results")
	if err != nil {
		return fmt.Errorf("failed to delete probe results: %w", err)
	}

	// Delete all domains
	_, err = db.Exec("DELETE FROM domains")
	if err != nil {
		return fmt.Errorf("failed to delete domains: %w", err)
	}

	return nil
}

// ClearTargetDomains deletes all domains and probe results for a specific target
func ClearTargetDomains(target string) error {
	if db == nil {
		if err := InitDB(); err != nil {
			return err
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	// Delete probe results for domains belonging to this target
	_, err := db.Exec(`
		DELETE FROM probe_results 
		WHERE domain IN (SELECT domain FROM domains WHERE target = ? OR target = '')
	`, target)
	if err != nil {
		return fmt.Errorf("failed to delete probe results: %w", err)
	}

	// Delete domains for this target
	_, err = db.Exec("DELETE FROM domains WHERE target = ? OR target = ''", target)
	if err != nil {
		return fmt.Errorf("failed to delete domains: %w", err)
	}

	return nil
}

// ClearScanState clears all scan state records
func ClearAllScanState() error {
	if db == nil {
		if err := InitDB(); err != nil {
			return err
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec("DELETE FROM scan_state")
	return err
}

// GetDatabaseStats returns statistics about the database
func GetDatabaseStats() (domainCount, probeCount, scanStateCount int, err error) {
	if db == nil {
		if err := InitDB(); err != nil {
			return 0, 0, 0, err
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	err = db.QueryRow("SELECT COUNT(*) FROM domains").Scan(&domainCount)
	if err != nil {
		return 0, 0, 0, err
	}

	err = db.QueryRow("SELECT COUNT(*) FROM probe_results").Scan(&probeCount)
	if err != nil {
		return 0, 0, 0, err
	}

	err = db.QueryRow("SELECT COUNT(*) FROM scan_state").Scan(&scanStateCount)
	if err != nil {
		return 0, 0, 0, err
	}

	return domainCount, probeCount, scanStateCount, nil
}

