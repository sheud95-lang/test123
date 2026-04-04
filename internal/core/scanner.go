package core

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"reaper/internal/config"
	"reaper/internal/extractors"
	"reaper/internal/utils"
)

type Scanner interface {
	Name() string
	Scan(client *http.Client, host string, port int, path string, isIP bool, scheme string) *ScanResult
}

type RateLimiter struct {
	mu     sync.Mutex
	rps    float64
	tokens float64
	maxTok float64
	lastT  time.Time
}

func NewRateLimiter(rps, burst int) *RateLimiter {
	return &RateLimiter{rps: float64(rps), tokens: float64(burst), maxTok: float64(burst), lastT: time.Now()}
}

func (rl *RateLimiter) Acquire() {
	for {
		rl.mu.Lock()
		now := time.Now()
		rl.tokens += now.Sub(rl.lastT).Seconds() * rl.rps
		if rl.tokens > rl.maxTok {
			rl.tokens = rl.maxTok
		}
		rl.lastT = now
		if rl.tokens >= 1.0 {
			rl.tokens--
			rl.mu.Unlock()
			return
		}
		rl.mu.Unlock()
		time.Sleep(time.Duration(float64(time.Second) / rl.rps))
	}
}

func GrabBanner(host string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(timeout))
	conn.Write([]byte(fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)))
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return string(buf[:n])
}

type ScannerEngine struct {
	Config   *config.ScanConfig
	Results  *ResultStore
	Treasure *TreasureWriter
	rl       *RateLimiter
	scanners map[string]Scanner
	client   *http.Client
	count    int64
	start    time.Time
	stop     int32
}

func NewScannerEngine(cfg *config.ScanConfig, rs *ResultStore, tw *TreasureWriter) *ScannerEngine {
	client := utils.NewHTTPClient(cfg.ConnectTimeout, cfg.ReadTimeout, cfg.TotalTimeout, cfg.MaxConnsPerHost, cfg.TotalConnectorLimit)
	return &ScannerEngine{
		Config: cfg, Results: rs, Treasure: tw,
		rl:       NewRateLimiter(cfg.TargetRPS, cfg.BurstSize),
		scanners: make(map[string]Scanner), client: client,
	}
}

func (se *ScannerEngine) RegisterScanner(s Scanner) { se.scanners[s.Name()] = s }

func (se *ScannerEngine) Stop() { atomic.StoreInt32(&se.stop, 1) }

func (se *ScannerEngine) isStopped() bool { return atomic.LoadInt32(&se.stop) != 0 }

// Scanners that need the full wordlist (every path).
// All others get only a small set of entry-point paths.
var fullPathScanners = map[string]bool{"path": true, "r2s": true}

// Entry-point paths for scanners that do their own internal path discovery.
var entryPaths = []string{"/", "/index.html", "/index.php", "/home", "/app"}

// pathsForScanner returns the path list a scanner should actually iterate.
// "path" and "r2s" get the full wordlist.
// "git", "uafr", "nvca", "js", "ajs" only need a few entry points —
// they discover their own sub-paths internally.
func pathsForScanner(name string, allPaths []string) []string {
	if fullPathScanners[name] {
		return allPaths
	}
	return entryPaths
}

func (se *ScannerEngine) ScanTarget(target *Target, paths []string, tg *TargetGenerator) {
	// L4 banner grab: once per target (not per path/scanner)
	if (se.Config.ScanMode == "L4" || se.Config.ScanMode == "L4+L7") && target.IsIP {
		banner := GrabBanner(target.Host, target.Port, se.Config.ConnectTimeout)
		if banner != "" {
			secrets := extractors.ExtractSecrets(banner, fmt.Sprintf("l4://%s:%d", target.Host, target.Port))
			if len(secrets) > 0 {
				r := ScanResult{
					URL:     fmt.Sprintf("l4://%s:%d", target.Host, target.Port),
					Scanner: "l4_banner", Secrets: secrets,
				}
				se.Results.AddResult(r)
				if se.Treasure != nil {
					se.Treasure.WriteFinding(r.URL, r.Scanner, secrets)
				}
			}
		}
	}

	if se.Config.ScanMode != "L7" && se.Config.ScanMode != "L4+L7" {
		return
	}

	scheme := "https"
	if target.Port == 80 || target.Port == 8080 {
		scheme = "http"
	}

	// Pre-probe: quick check if target is alive before committing to all paths
	probeURL := fmt.Sprintf("%s://%s:%d/", scheme, target.Host, target.Port)
	probe := utils.Fetch(se.client, probeURL, "HEAD", nil, 0, 0)
	if probe == nil {
		return // target dead, skip entirely
	}

	for sName, scanner := range se.scanners {
		if se.isStopped() {
			return
		}
		enabled := false
		for _, en := range se.Config.EnabledScanners {
			if en == sName {
				enabled = true
				break
			}
		}
		if !enabled {
			continue
		}

		scanPaths := pathsForScanner(sName, paths)
		for _, path := range scanPaths {
			if se.isStopped() {
				return
			}
			se.rl.Acquire()

			result := scanner.Scan(se.client, target.Host, target.Port, path, target.IsIP, scheme)
			if result != nil {
				added := se.Results.AddResult(*result)
				if added {
					if tg != nil && len(result.NewTargets) > 0 {
						tg.AddFromParsedContent(strings.Join(result.NewTargets, "\n"), se.Config.Ports)
					}
					if se.Treasure != nil && len(result.Secrets) > 0 {
						se.Treasure.WriteFinding(result.URL, result.Scanner, result.Secrets)
						envSecrets := extractors.ExtractEnvPairs(collectRawLines(result.Secrets), result.URL)
						if len(envSecrets) > 0 {
							se.Treasure.WriteEnvDump(result.URL, result.Scanner, envSecrets)
						}
					}
					log.Printf("[%s] %s -> %d secrets, %d targets",
						sName, result.URL, len(result.Secrets), len(result.NewTargets))
				}
			}

			atomic.AddInt64(&se.count, 1)
			if se.Config.DelayJitterMaxMs > 0 {
				j := time.Duration(rand.Intn(se.Config.DelayJitterMaxMs-se.Config.DelayJitterMinMs)+se.Config.DelayJitterMinMs) * time.Millisecond
				time.Sleep(j)
			}
		}
	}
}

func collectRawLines(secrets []extractors.Secret) string {
	var lines []string
	seen := make(map[string]bool)
	for _, s := range secrets {
		if s.RawLine != "" && !seen[s.RawLine] {
			seen[s.RawLine] = true
			lines = append(lines, s.RawLine)
		}
	}
	return strings.Join(lines, "\n")
}

func (se *ScannerEngine) Run(targets []*Target, paths []string, tg *TargetGenerator) {
	se.start = time.Now()
	se.count = 0
	sem := make(chan struct{}, se.Config.MaxConcurrentReqs)
	var wg sync.WaitGroup

	// Estimate: path+r2s get full wordlist, others get entryPaths only
	fullCount, entryCount := 0, 0
	for _, en := range se.Config.EnabledScanners {
		if fullPathScanners[en] {
			fullCount++
		} else {
			entryCount++
		}
	}
	estReqs := len(targets) * (fullCount*len(paths) + entryCount*len(entryPaths))
	log.Printf("Scan: %d targets | %d paths | %d scanners (est ~%d reqs, %d full-path + %d entry-only)",
		len(targets), len(paths), len(se.Config.EnabledScanners), estReqs, fullCount, entryCount)

	batchSize := 500
	for i := 0; i < len(targets); i += batchSize {
		if se.isStopped() {
			break
		}
		end := i + batchSize
		if end > len(targets) {
			end = len(targets)
		}
		for _, t := range targets[i:end] {
			wg.Add(1)
			go func(tgt *Target) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				se.ScanTarget(tgt, paths, tg)
			}(t)
		}
		wg.Wait()

		elapsed := time.Since(se.start).Seconds()
		c := atomic.LoadInt64(&se.count)
		rps := float64(0)
		if elapsed > 0 {
			rps = float64(c) / elapsed
		}
		stats := se.Results.Stats()
		log.Printf("Progress: %d/%d | %d reqs | %.0f RPS | Secret hits: %d | Unique secrets: %d | New targets: %d",
			end, len(targets), c, rps,
			stats["hits_with_secrets"], stats["total_secrets"], stats["total_new_targets"])

		if tg != nil {
			existing := make(map[string]bool)
			for _, t := range targets {
				existing[fmt.Sprintf("%s:%d", t.Host, t.Port)] = true
			}
			var chain []*Target
			for _, nt := range tg.GetTargets() {
				if nt.Priority > 0 && !existing[fmt.Sprintf("%s:%d", nt.Host, nt.Port)] {
					chain = append(chain, nt)
					if len(chain) >= 100 {
						break
					}
				}
			}
			if len(chain) > 0 {
				log.Printf("Chaining: %d new targets", len(chain))
				for _, t := range chain {
					wg.Add(1)
					go func(tgt *Target) {
						defer wg.Done()
						sem <- struct{}{}
						defer func() { <-sem }()
						se.ScanTarget(tgt, paths, tg)
					}(t)
				}
				wg.Wait()
			}
		}
	}

	elapsed := time.Since(se.start).Seconds()
	c := atomic.LoadInt64(&se.count)
	rps := float64(0)
	if elapsed > 0 {
		rps = float64(c) / elapsed
	}
	log.Printf("Done: %d reqs in %.1fs (%.0f RPS)", c, elapsed, rps)
}