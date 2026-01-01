package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Result represents a scan result for output
type Result struct {
	Domain        string    `json:"domain"`
	Target        string    `json:"target"`
	URL           string    `json:"url,omitempty"`
	StatusCode    int       `json:"status_code,omitempty"`
	ContentLength int64     `json:"content_length,omitempty"`
	Title         string    `json:"title,omitempty"`
	Server        string    `json:"server,omitempty"`
	Technologies  []string  `json:"technologies,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// Writer handles output to files
type Writer struct {
	format   string
	filePath string
	file     *os.File
	csvWriter *csv.Writer
	results  []Result
}

// NewWriter creates a new output writer
func NewWriter(filePath, format string) (*Writer, error) {
	if filePath == "" {
		return nil, nil
	}

	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	w := &Writer{
		format:   strings.ToLower(format),
		filePath: filePath,
		file:     file,
		results:  make([]Result, 0),
	}

	if w.format == "csv" {
		w.csvWriter = csv.NewWriter(file)
		// Write header
		w.csvWriter.Write([]string{"domain", "target", "url", "status_code", "content_length", "title", "server", "technologies", "timestamp"})
	}

	return w, nil
}

// Write writes a result to the output
func (w *Writer) Write(result Result) error {
	if w == nil {
		return nil
	}

	switch w.format {
	case "json", "jsonl":
		return w.writeJSON(result)
	case "csv":
		return w.writeCSV(result)
	case "txt", "text":
		return w.writeTXT(result)
	default:
		return w.writeTXT(result)
	}
}

func (w *Writer) writeJSON(result Result) error {
	w.results = append(w.results, result)
	return nil
}

func (w *Writer) writeCSV(result Result) error {
	techs := strings.Join(result.Technologies, "|")
	record := []string{
		result.Domain,
		result.Target,
		result.URL,
		fmt.Sprintf("%d", result.StatusCode),
		fmt.Sprintf("%d", result.ContentLength),
		result.Title,
		result.Server,
		techs,
		result.Timestamp.Format(time.RFC3339),
	}
	return w.csvWriter.Write(record)
}

func (w *Writer) writeTXT(result Result) error {
	line := result.Domain
	if result.URL != "" {
		line = result.URL
	}
	if result.StatusCode > 0 {
		line = fmt.Sprintf("%s [%d] [%d]", line, result.StatusCode, result.ContentLength)
	}
	if result.Title != "" {
		line = fmt.Sprintf("%s [%s]", line, result.Title)
	}
	_, err := fmt.Fprintln(w.file, line)
	return err
}

// Close closes the output writer
func (w *Writer) Close() error {
	if w == nil || w.file == nil {
		return nil
	}

	if w.format == "json" && len(w.results) > 0 {
		encoder := json.NewEncoder(w.file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(w.results); err != nil {
			return err
		}
	}

	if w.csvWriter != nil {
		w.csvWriter.Flush()
	}

	return w.file.Close()
}

// WriteDomainOnly writes just the domain name (for silent mode)
func WriteDomainOnly(domain string) {
	fmt.Println(domain)
}

