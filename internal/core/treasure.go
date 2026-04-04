package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"reaper/internal/extractors"
)

type TreasureWriter struct {
	mu             sync.Mutex
	treasureDir    string
	hitsFile       *os.File
	allFile        *os.File
	allValidFile   *os.File
	serviceFiles   map[string]*os.File
	stats          map[string]int
	seenEntries    map[string]bool
	allByService   map[string][]string // aggregated for all.txt
	validByService map[string][]string // aggregated for all_valid.txt
}

func NewTreasureWriter(outputDir string) *TreasureWriter {
	tDir := filepath.Join(outputDir, "treasure")
	os.MkdirAll(tDir, 0o755)

	hf, _ := os.OpenFile(filepath.Join(outputDir, "hits_live.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	af, _ := os.OpenFile(filepath.Join(tDir, "all.txt"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	avf, _ := os.OpenFile(filepath.Join(tDir, "all_valid.txt"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)

	return &TreasureWriter{
		treasureDir:  tDir,
		hitsFile:     hf,
		allFile:      af,
		allValidFile: avf,
		serviceFiles:   make(map[string]*os.File),
		stats:          make(map[string]int),
		seenEntries:    make(map[string]bool),
		allByService:   make(map[string][]string),
		validByService: make(map[string][]string),
	}
}

func (tw *TreasureWriter) getServiceFile(service string) *os.File {
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
	tw.serviceFiles[service] = f
	return f
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

	ts := time.Now().UTC().Format("15:04:05")
	for _, s := range secrets {
		tag := ""
		if s.Service != "" && s.Service != "smtp" && s.Service != "auth" {
			tag = " [" + s.Service + "]"
		}
		line := fmt.Sprintf("[%s] %s — %s: %s%s\n", ts, sourceURL, s.Type, s.Value, tag)
		tw.hitsFile.Write([]byte(line))
	}

	svcGroups := make(map[string][]extractors.Secret)
	smtpData := make(map[string]string)

	for _, s := range secrets {
		svc := s.Service
		if svc == "" {
			continue
		}
		svcGroups[svc] = append(svcGroups[svc], s)

		if svc == "smtp" {
			lower := strings.ToLower(s.Type)
			switch {
			case strings.Contains(lower, "host"):
				smtpData["host"] = s.Value
			case strings.Contains(lower, "user"):
				smtpData["user"] = s.Value
			case strings.Contains(lower, "pass"):
				smtpData["password"] = s.Value
			case strings.Contains(lower, "port"):
				smtpData["port"] = s.Value
			case strings.Contains(lower, "url"):
				smtpData["url"] = s.Value
			}
			if _, ok := smtpData["provider"]; !ok {
				host := smtpData["host"]
				if host == "" {
					host = s.Value
				}
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
						smtpData["provider"] = p.name
						break
					}
				}
			}
		}
	}

	for svc, svcSecrets := range svcGroups {
		f := tw.getServiceFile(svc)
		if f == nil {
			continue
		}

		header := fmt.Sprintf("\n%s - %s\n", sourceURL, scanType)
		header += strings.Repeat("-", minInt(len(strings.TrimSpace(header)), 80)) + "\n"
		f.Write([]byte(header))

		if svc == "smtp" {
			if p, ok := smtpData["provider"]; ok && p != "" {
				f.Write([]byte(fmt.Sprintf("provider: %s\n", p)))
			}
			for _, k := range []string{"host", "port", "user", "password", "url"} {
				if v, ok := smtpData[k]; ok && v != "" {
					f.Write([]byte(fmt.Sprintf("smtp_%s: %s\n", k, v)))
				}
			}
		} else if svc == "database" {
			for _, s := range svcSecrets {
				provider := detectDBProvider(s.Value)
				tag := ""
				if provider != "" {
					tag = " [" + provider + "]"
				}
				f.Write([]byte(fmt.Sprintf("%s%s: %s\n", s.Type, tag, s.Value)))
			}
		} else {
			for _, s := range svcSecrets {
				f.Write([]byte(fmt.Sprintf("%s: %s\n", s.Type, s.Value)))
			}
		}
		f.Write([]byte("\n"))
		tw.stats[svc] += len(svcSecrets)
	}

	// Accumulate for aggregated all.txt (written in Close)
	for svc, svcSecrets := range svcGroups {
		if svc == "smtp" || svc == "auth" {
			continue
		}
		for _, s := range svcSecrets {
			tw.allByService[svc] = append(tw.allByService[svc], s.Value)
		}
	}
}

func (tw *TreasureWriter) WriteValid(sourceURL, service, key, detail string) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if f := tw.getServiceFile(service); f != nil {
		f.Write([]byte(fmt.Sprintf("[VALID] %s — %s\n  Source: %s\n\n", key, detail, sourceURL)))
	}
	// Accumulate for aggregated all_valid.txt (written in Close)
	tw.validByService[service] = append(tw.validByService[service], key)
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
	// Accumulate for aggregated all.txt (written in Close)
	for svc, keys := range svcGroups {
		tw.allByService[svc] = append(tw.allByService[svc], keys...)
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

func (tw *TreasureWriter) Close() {
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
			tw.allFile.Write([]byte(fmt.Sprintf("%s - %d hits\n", svc, len(vals))))
			for _, v := range vals {
				tw.allFile.Write([]byte(v + "\n"))
			}
			tw.allFile.Write([]byte("\n"))
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
			tw.allValidFile.Write([]byte(fmt.Sprintf("%s - %d hits\n", svc, len(vals))))
			for _, v := range vals {
				tw.allValidFile.Write([]byte(v + "\n"))
			}
			tw.allValidFile.Write([]byte("\n"))
		}
	}

	for _, f := range []*os.File{tw.hitsFile, tw.allFile, tw.allValidFile} {
		if f != nil {
			f.Close()
		}
	}
	for _, f := range tw.serviceFiles {
		f.Close()
	}
}

func detectDBProvider(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "postgres"):
		return "postgresql"
	case strings.HasPrefix(lower, "mysql"):
		return "mysql"
	case strings.HasPrefix(lower, "mongodb"):
		return "mongodb"
	case strings.HasPrefix(lower, "redis"):
		return "redis"
	case strings.HasPrefix(lower, "amqp"):
		return "rabbitmq"
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}