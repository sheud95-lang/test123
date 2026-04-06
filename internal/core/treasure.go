package core

import (
	"bufio"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"reaper/internal/extractors"
)

type smtpEntry struct {
	Source   string
	Host     string
	Port     string
	User     string
	Password string
	URL      string
	Provider string
}

func (e *smtpEntry) String() string {
	var parts []string
	if e.Provider != "" {
		parts = append(parts, "provider: "+e.Provider)
	}
	if e.Host != "" {
		parts = append(parts, "host: "+e.Host)
	}
	if e.Port != "" {
		parts = append(parts, "port: "+e.Port)
	}
	if e.User != "" {
		parts = append(parts, "user: "+e.User)
	}
	if e.Password != "" {
		parts = append(parts, "password: "+e.Password)
	}
	if e.URL != "" {
		parts = append(parts, "url: "+e.URL)
	}
	return strings.Join(parts, " | ")
}

type bufferedFile struct {
	f *os.File
	w *bufio.Writer
}

func newBufferedFile(f *os.File) *bufferedFile {
	if f == nil {
		return nil
	}
	return &bufferedFile{f: f, w: bufio.NewWriterSize(f, 64*1024)}
}

func (bf *bufferedFile) Write(p []byte) { bf.w.Write(p) }
func (bf *bufferedFile) WriteString(s string) { bf.w.WriteString(s) }
func (bf *bufferedFile) Flush() { bf.w.Flush() }
func (bf *bufferedFile) Close() {
	bf.w.Flush()
	bf.f.Close()
}

type TreasureWriter struct {
	mu             sync.Mutex
	treasureDir    string
	hitsFile       *bufferedFile
	allFile        *bufferedFile
	allValidFile   *bufferedFile
	serviceFiles   map[string]*bufferedFile
	stats          map[string]int
	seenEntries    map[string]bool
	allByService   map[string][]string    // aggregated for all.txt
	allSeen        map[string]map[string]bool // dedup: service -> set of values
	validByService map[string][]string // aggregated for all_valid.txt
	validSeen      map[string]map[string]bool // dedup
	smtpEntries    []*smtpEntry        // accumulated SMTP connection blocks
	pathHits       map[string]int     // path -> hit count for leaderboard
	stopFlush      chan struct{}
}

func NewTreasureWriter(outputDir string) *TreasureWriter {
	tDir := filepath.Join(outputDir, "treasure")
	os.MkdirAll(tDir, 0o755)

	hf, _ := os.OpenFile(filepath.Join(outputDir, "hits_live.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	af, _ := os.OpenFile(filepath.Join(tDir, "all.txt"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	avf, _ := os.OpenFile(filepath.Join(tDir, "all_valid.txt"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)

	tw := &TreasureWriter{
		treasureDir:    tDir,
		hitsFile:       newBufferedFile(hf),
		allFile:        newBufferedFile(af),
		allValidFile:   newBufferedFile(avf),
		serviceFiles:   make(map[string]*bufferedFile),
		stats:          make(map[string]int),
		seenEntries:    make(map[string]bool),
		allByService:   make(map[string][]string),
		allSeen:        make(map[string]map[string]bool),
		validByService: make(map[string][]string),
		validSeen:      make(map[string]map[string]bool),
		smtpEntries:    nil,
		pathHits:       make(map[string]int),
		stopFlush:      make(chan struct{}),
	}

	// Periodic flush every 5 seconds
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				tw.flushAll()
			case <-tw.stopFlush:
				return
			}
		}
	}()

	return tw
}

func (tw *TreasureWriter) getServiceFile(service string) *bufferedFile {
	if service == "" {
		return nil
	}
	service = strings.ToLower(strings.ReplaceAll(service, " ", "_"))
	if f, ok := tw.serviceFiles[service]; ok {
		return f
	}
	f, err := os.OpenFile(filepath.Join(tw.treasureDir, service+".txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil
	}
	bf := newBufferedFile(f)
	tw.serviceFiles[service] = bf
	return bf
}

func (tw *TreasureWriter) WriteFinding(sourceURL, scanType string, secrets []extractors.Secret) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	// Filter already-seen secrets (dedup by type:value, not by URL)
	var newSecrets []extractors.Secret
	for _, s := range secrets {
		key := s.Type + ":" + s.Value
		if !tw.seenEntries[key] {
			tw.seenEntries[key] = true
			newSecrets = append(newSecrets, s)
		}
	}
	if len(newSecrets) == 0 {
		return
	}
	secrets = newSecrets

	// Track path hits for leaderboard
	if u, err := url.Parse(sourceURL); err == nil {
		p := u.Path
		if p == "" {
			p = "/"
		}
		tw.pathHits[p] += len(secrets)
	}

	ts := time.Now().UTC().Format("15:04:05")
	for _, s := range secrets {
		tag := ""
		if s.Service != "" && s.Service != "smtp" && s.Service != "auth" {
			tag = " [" + s.Service + "]"
		}
		line := fmt.Sprintf("[%s] %s — %s: %s%s\n", ts, sourceURL, s.Type, s.Value, tag)
		tw.hitsFile.WriteString(line)

		// Real-time hit notification to stdout
		val := s.Value
		if len(val) > 40 {
			val = val[:37] + "..."
		}
		log.Printf("[HIT] %s — %s: %s%s", sourceURL, s.Type, val, tag)
	}

	svcGroups := make(map[string][]extractors.Secret)
	var smtpSecrets []extractors.Secret

	for _, s := range secrets {
		svc := s.Service
		if svc == "" {
			continue
		}
		if svc == "smtp" {
			smtpSecrets = append(smtpSecrets, s)
		} else {
			svcGroups[svc] = append(svcGroups[svc], s)
		}
	}

	// SMTP: combine all fields into one connection entry
	if len(smtpSecrets) > 0 {
		entry := &smtpEntry{Source: sourceURL}
		for _, s := range smtpSecrets {
			lower := strings.ToLower(s.Type)
			switch {
			case strings.Contains(lower, "url"):
				entry.URL = s.Value
			case strings.Contains(lower, "host") || strings.Contains(lower, "server"):
				entry.Host = s.Value
			case strings.Contains(lower, "user"):
				entry.User = s.Value
			case strings.Contains(lower, "pass"):
				entry.Password = s.Value
			case strings.Contains(lower, "port"):
				entry.Port = s.Value
			}
		}
		// Detect provider from host
		host := entry.Host
		if host == "" {
			host = entry.URL
		}
		if host != "" {
			hl := strings.ToLower(host)
			providers := []struct{ sub, name string }{
				{"sendgrid", "sendgrid"}, {"sg.", "sendgrid"},
				{"mailgun", "mailgun"}, {"amazonaws", "aws_ses"},
				{"ses.", "aws_ses"}, {"mailchimp", "mailchimp"},
				{"mandrill", "mailchimp"}, {"postmark", "postmark"},
				{"sparkpost", "sparkpost"}, {"gmail", "gmail"},
				{"google", "gmail"}, {"outlook", "microsoft"},
				{"office365", "microsoft"}, {"yandex", "yandex"},
			}
			for _, p := range providers {
				if strings.Contains(hl, p.sub) {
					entry.Provider = p.name
					break
				}
			}
		}
		tw.smtpEntries = append(tw.smtpEntries, entry)
		tw.stats["smtp"] += len(smtpSecrets)

		// Write to smtp.txt
		if f := tw.getServiceFile("smtp"); f != nil {
			header := fmt.Sprintf("\n%s - %s\n", sourceURL, scanType)
			header += strings.Repeat("-", minInt(len(strings.TrimSpace(header)), 80)) + "\n"
			f.WriteString(header)
			if entry.Provider != "" {
				f.WriteString(fmt.Sprintf("provider: %s\n", entry.Provider))
			}
			if entry.Host != "" {
				f.WriteString(fmt.Sprintf("host: %s\n", entry.Host))
			}
			if entry.Port != "" {
				f.WriteString(fmt.Sprintf("port: %s\n", entry.Port))
			}
			if entry.User != "" {
				f.WriteString(fmt.Sprintf("user: %s\n", entry.User))
			}
			if entry.Password != "" {
				f.WriteString(fmt.Sprintf("password: %s\n", entry.Password))
			}
			if entry.URL != "" {
				f.WriteString(fmt.Sprintf("url: %s\n", entry.URL))
			}
			f.WriteString("\n")
		}
	}

	// Non-SMTP services: write to per-service files
	for svc, svcSecrets := range svcGroups {
		f := tw.getServiceFile(svc)
		if f == nil {
			continue
		}
		header := fmt.Sprintf("\n%s - %s\n", sourceURL, scanType)
		header += strings.Repeat("-", minInt(len(strings.TrimSpace(header)), 80)) + "\n"
		f.WriteString(header)
		for _, s := range svcSecrets {
			f.WriteString(fmt.Sprintf("%s: %s\n", s.Type, s.Value))
		}
		f.WriteString("\n")
		tw.stats[svc] += len(svcSecrets)
	}

	// Accumulate for aggregated all.txt (written in Close) — deduplicated
	for svc, svcSecrets := range svcGroups {
		if excludeFromAll[svc] {
			continue
		}
		for _, s := range svcSecrets {
			tw.addToAll(svc, s.Value)
		}
	}
}

var excludeFromAll = map[string]bool{"smtp": true, "auth": true, "jwt": true, "firebase": true, "google": true}

func (tw *TreasureWriter) WriteValid(sourceURL, service, key, detail string) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if f := tw.getServiceFile(service); f != nil {
		f.WriteString(fmt.Sprintf("[VALID] %s — %s\n  Source: %s\n\n", key, detail, sourceURL))
	}
	// Accumulate for aggregated all_valid.txt (written in Close) — deduplicated
	if !excludeFromAll[service] {
		tw.addToValid(service, key)
	}
}

func (tw *TreasureWriter) WriteEnvDump(sourceURL, scanType string, envSecrets []extractors.Secret) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	svcGroups := make(map[string][]string)
	for _, s := range envSecrets {
		svc := s.Service
		if svc == "" {
			continue
		}
		display := s.Value
		if s.KeyName != "" {
			display = s.KeyName + "=" + s.Value
		}
		svcGroups[svc] = append(svcGroups[svc], display)
	}
	// Accumulate for aggregated all.txt (written in Close) — deduplicated
	for svc, keys := range svcGroups {
		if !excludeFromAll[svc] {
			for _, k := range keys {
				tw.addToAll(svc, k)
			}
		}
	}
}

func (tw *TreasureWriter) GetStats() map[string]int {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	out := make(map[string]int)
	for k, v := range tw.stats {
		out[k] = v
	}
	return out
}

func (tw *TreasureWriter) flushAll() {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.hitsFile != nil {
		tw.hitsFile.Flush()
	}
	for _, f := range tw.serviceFiles {
		f.Flush()
	}
}

func (tw *TreasureWriter) Close() {
	// Stop periodic flusher
	close(tw.stopFlush)

	tw.mu.Lock()
	defer tw.mu.Unlock()

	// Write aggregated all.txt: service-centric with hit counts
	if len(tw.allByService) > 0 {
		var svcs []string
		for svc := range tw.allByService {
			svcs = append(svcs, svc)
		}
		sort.Strings(svcs)
		for _, svc := range svcs {
			vals := tw.allByService[svc]
			tw.allFile.WriteString(fmt.Sprintf("%s - %d hits\n", svc, len(vals)))
			for _, v := range vals {
				tw.allFile.WriteString(v + "\n")
			}
			tw.allFile.WriteString("\n")
		}
	}

	// Write aggregated all_valid.txt: service-centric with hit counts
	if len(tw.validByService) > 0 {
		var svcs []string
		for svc := range tw.validByService {
			svcs = append(svcs, svc)
		}
		sort.Strings(svcs)
		for _, svc := range svcs {
			vals := tw.validByService[svc]
			tw.allValidFile.WriteString(fmt.Sprintf("%s - %d hits\n", svc, len(vals)))
			for _, v := range vals {
				tw.allValidFile.WriteString(v + "\n")
			}
			tw.allValidFile.WriteString("\n")
		}
	}

	// Write path leaderboard
	if len(tw.pathHits) > 0 {
		type pathStat struct {
			path  string
			count int
		}
		var sorted []pathStat
		for p, c := range tw.pathHits {
			sorted = append(sorted, pathStat{p, c})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })
		lbPath := filepath.Join(tw.treasureDir, "path_leaderboard.txt")
		if f, err := os.Create(lbPath); err == nil {
			w := bufio.NewWriter(f)
			w.WriteString("Path Leaderboard — Top paths by secret hits\n")
			w.WriteString(strings.Repeat("=", 50) + "\n\n")
			limit := len(sorted)
			if limit > 100 {
				limit = 100
			}
			for i := 0; i < limit; i++ {
				w.WriteString(fmt.Sprintf("%4d | %s\n", sorted[i].count, sorted[i].path))
			}
			w.Flush()
			f.Close()
		}
	}

	for _, bf := range []*bufferedFile{tw.hitsFile, tw.allFile, tw.allValidFile} {
		if bf != nil {
			bf.Close()
		}
	}
	for _, bf := range tw.serviceFiles {
		bf.Close()
	}
}

func (tw *TreasureWriter) addToAll(svc, value string) {
	if tw.allSeen[svc] == nil {
		tw.allSeen[svc] = make(map[string]bool)
	}
	if !tw.allSeen[svc][value] {
		tw.allSeen[svc][value] = true
		tw.allByService[svc] = append(tw.allByService[svc], value)
	}
}

func (tw *TreasureWriter) addToValid(svc, value string) {
	if tw.validSeen[svc] == nil {
		tw.validSeen[svc] = make(map[string]bool)
	}
	if !tw.validSeen[svc][value] {
		tw.validSeen[svc][value] = true
		tw.validByService[svc] = append(tw.validByService[svc], value)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}