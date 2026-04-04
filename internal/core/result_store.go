package core

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"reaper/internal/extractors"
)

type ScanResult struct {
	URL          string
	Status       int
	Scanner      string
	Secrets      []extractors.Secret
	NewTargets   []string
	ResponseSize int
	Timestamp    string
}

type ResultStore struct {
	mu               sync.Mutex
	results          []ScanResult
	seenURLs         map[string]bool
	seenSecrets      map[string]bool
	TotalScanned     int
	TotalSecrets     int
	TotalNewTargets  int
	HitsWithSecrets  int
	outputDir        string
	autosaveStop     chan struct{}
}

func NewResultStore(outputDir string) *ResultStore {
	return &ResultStore{
		seenURLs:    make(map[string]bool),
		seenSecrets: make(map[string]bool),
		outputDir:   outputDir,
	}
}

func (rs *ResultStore) AddResult(r ScanResult) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.TotalScanned++
	if r.Timestamp == "" {
		r.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if len(r.Secrets) == 0 && len(r.NewTargets) == 0 {
		return false
	}
	if rs.seenURLs[r.URL] {
		return false
	}
	var newS []extractors.Secret
	for _, s := range r.Secrets {
		k := s.Type + ":" + s.Value
		if !rs.seenSecrets[k] {
			rs.seenSecrets[k] = true
			newS = append(newS, s)
		}
	}
	if len(newS) == 0 && len(r.NewTargets) == 0 {
		return false
	}
	r.Secrets = newS
	rs.results = append(rs.results, r)
	rs.seenURLs[r.URL] = true
	rs.TotalSecrets += len(newS)
	rs.TotalNewTargets += len(r.NewTargets)
	if len(newS) > 0 {
		rs.HitsWithSecrets++
	}
	return true
}

func (rs *ResultStore) Stats() map[string]int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return map[string]int{
		"total_scanned":      rs.TotalScanned,
		"total_results":      len(rs.results),
		"total_secrets":      rs.TotalSecrets,
		"hits_with_secrets":  rs.HitsWithSecrets,
		"total_new_targets":  rs.TotalNewTargets,
	}
}

func (rs *ResultStore) StartAutosave(interval time.Duration) {
	rs.autosaveStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rs.SaveNow()
			case <-rs.autosaveStop:
				return
			}
		}
	}()
}

func (rs *ResultStore) StopAutosave() {
	if rs.autosaveStop != nil {
		close(rs.autosaveStop)
	}
}

func (rs *ResultStore) SaveNow() {
	rs.ExportJSON(filepath.Join(rs.outputDir, "results.json"))
	rs.ExportCSV(filepath.Join(rs.outputDir, "results.csv"))
}

func (rs *ResultStore) ExportJSON(fpath string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	os.MkdirAll(filepath.Dir(fpath), 0o755)
	type jS struct {
		Type    string `json:"type"`
		Value   string `json:"value"`
		Service string `json:"service,omitempty"`
		Context string `json:"context,omitempty"`
		Line    int    `json:"line,omitempty"`
	}
	type jR struct {
		URL     string   `json:"url"`
		Status  int      `json:"status"`
		Scanner string   `json:"scanner"`
		TS      string   `json:"timestamp"`
		Secrets []jS     `json:"secrets"`
		NT      []string `json:"new_targets,omitempty"`
	}
	var results []jR
	for _, r := range rs.results {
		var ss []jS
		for _, s := range r.Secrets {
			ss = append(ss, jS{Type: s.Type, Value: s.Value, Service: s.Service, Context: s.Context, Line: s.Line})
		}
		results = append(results, jR{URL: r.URL, Status: r.Status, Scanner: r.Scanner, TS: r.Timestamp, Secrets: ss, NT: r.NewTargets})
	}
	data, _ := json.MarshalIndent(struct {
		Date    string         `json:"scan_date"`
		Stats   map[string]int `json:"stats"`
		Results []jR           `json:"results"`
	}{
		time.Now().UTC().Format(time.RFC3339),
		map[string]int{"total_scanned": rs.TotalScanned, "total_secrets": rs.TotalSecrets, "total_new_targets": rs.TotalNewTargets},
		results,
	}, "", "  ")
	return os.WriteFile(fpath, data, 0o644)
}

func (rs *ResultStore) ExportCSV(fpath string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	os.MkdirAll(filepath.Dir(fpath), 0o755)
	f, err := os.Create(fpath)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"url", "status", "scanner", "type", "value", "service", "timestamp"})
	for _, r := range rs.results {
		for _, s := range r.Secrets {
			w.Write([]string{r.URL, fmt.Sprintf("%d", r.Status), r.Scanner, s.Type, s.Value, s.Service, r.Timestamp})
		}
	}
	return nil
}

func (rs *ResultStore) Summary() string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var sb strings.Builder
	sb.WriteString("=== Reaper Scan Summary ===\n")
	sb.WriteString(fmt.Sprintf("Total requests:    %d\n", rs.TotalScanned))
	sb.WriteString(fmt.Sprintf("Hits (secrets):    %d\n", rs.HitsWithSecrets))
	sb.WriteString(fmt.Sprintf("Hits (targets):    %d\n", len(rs.results)))
	sb.WriteString(fmt.Sprintf("Unique secrets:    %d\n", rs.TotalSecrets))
	sb.WriteString(fmt.Sprintf("New targets found: %d\n", rs.TotalNewTargets))
	tc := make(map[string]int)
	for _, r := range rs.results {
		for _, s := range r.Secrets {
			tc[s.Type]++
		}
	}
	type kv struct {
		K string
		V int
	}
	var sorted []kv
	for k, v := range tc {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].V > sorted[j].V })
	sb.WriteString("\nSecrets by type:\n")
	for _, item := range sorted {
		sb.WriteString(fmt.Sprintf("  %s: %d\n", item.K, item.V))
	}
	return sb.String()
}