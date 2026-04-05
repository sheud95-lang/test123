package core

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/valyala/fasthttp"

	"reaper/internal/config"
	"reaper/internal/extractors"
	"reaper/internal/utils"
)

type Scanner interface {
	Name() string
	Scan(client *fasthttp.Client, host string, port int, path string, isIP bool, scheme string) *ScanResult
}

// ---- Lock-free rate limiter (atomic CAS) ----

type atomicFloat64 struct {
	v uint64
}

func (a *atomicFloat64) Load() float64 {
	bits := atomic.LoadUint64(&a.v)
	return *(*float64)(unsafe.Pointer(&bits))
}

func (a *atomicFloat64) Store(val float64) {
	bits := *(*uint64)(unsafe.Pointer(&val))
	atomic.StoreUint64(&a.v, bits)
}

func (a *atomicFloat64) CAS(old, new float64) bool {
	oldBits := *(*uint64)(unsafe.Pointer(&old))
	newBits := *(*uint64)(unsafe.Pointer(&new))
	return atomic.CompareAndSwapUint64(&a.v, oldBits, newBits)
}

type RateLimiter struct {
	rps    float64
	maxTok float64
	tokens atomicFloat64
	lastNs int64 // unix nanos
}

func NewRateLimiter(rps, burst int) *RateLimiter {
	rl := &RateLimiter{rps: float64(rps), maxTok: float64(burst)}
	rl.tokens.Store(float64(burst))
	atomic.StoreInt64(&rl.lastNs, time.Now().UnixNano())
	return rl
}

func (rl *RateLimiter) Acquire() {
	sleepDur := time.Duration(float64(time.Second) / rl.rps)
	for {
		now := time.Now().UnixNano()
		lastNs := atomic.LoadInt64(&rl.lastNs)
		elapsed := float64(now-lastNs) / 1e9

		// Combined refill + consume in a single CAS loop to prevent burst spikes
		for {
			cur := rl.tokens.Load()
			newTok := cur
			// Refill based on elapsed time (only if we can claim the timestamp)
			if elapsed > 0 {
				newTok = cur + elapsed*rl.rps
				if newTok > rl.maxTok {
					newTok = rl.maxTok
				}
			}
			if newTok < 1.0 {
				break // not enough tokens even after refill
			}
			// Try to consume one token atomically
			if rl.tokens.CAS(cur, newTok-1.0) {
				// Update timestamp only on successful consume
				atomic.CompareAndSwapInt64(&rl.lastNs, lastNs, now)
				return
			}
		}
		time.Sleep(sleepDur)
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

type scannerEntry struct {
	name    string
	scanner Scanner
}

type ScannerEngine struct {
	Config   *config.ScanConfig
	Results  *ResultStore
	Treasure *TreasureWriter
	rl       *RateLimiter
	scanners []scannerEntry // ordered slice for deterministic iteration
	client   *fasthttp.Client
	count       int64
	scanCounts  map[string]*int64 // per-scanner call counter
	start       time.Time
	stop        int32
}

func NewScannerEngine(cfg *config.ScanConfig, rs *ResultStore, tw *TreasureWriter) *ScannerEngine {
	client := utils.NewFastHTTPClient(cfg.ConnectTimeout, cfg.ReadTimeout, cfg.TotalTimeout, cfg.MaxConnsPerHost, cfg.TotalConnectorLimit)
	return &ScannerEngine{
		Config: cfg, Results: rs, Treasure: tw,
		rl:         NewRateLimiter(cfg.TargetRPS, cfg.BurstSize),
		client:     client,
		scanCounts: make(map[string]*int64),
	}
}

func (se *ScannerEngine) RegisterScanner(s Scanner) {
	se.scanners = append(se.scanners, scannerEntry{name: s.Name(), scanner: s})
	cnt := int64(0)
	se.scanCounts[s.Name()] = &cnt
}

func (se *ScannerEngine) Stop() { atomic.StoreInt32(&se.stop, 1) }

func (se *ScannerEngine) ScannerStats() string {
	var parts []string
	for name, cnt := range se.scanCounts {
		parts = append(parts, fmt.Sprintf("%s=%d", name, atomic.LoadInt64(cnt)))
	}
	elapsed := time.Since(se.start).Seconds()
	c := atomic.LoadInt64(&se.count)
	rps := float64(0)
	if elapsed > 0 {
		rps = float64(c) / elapsed
	}
	return fmt.Sprintf("%d reqs in %.1fs (%.0f RPS) | Scanner calls: %s", c, elapsed, rps, strings.Join(parts, ", "))
}

func (se *ScannerEngine) isStopped() bool { return atomic.LoadInt32(&se.stop) != 0 }

// Scanners that need the full wordlist (every path).
var fullPathScanners = map[string]bool{"path": true, "r2s": true}

// Strategic entry points for discovery scanners.
// These hit different app sections that may have different JS, hidden inputs, backup files.
var entryPaths = []string{
	"/",
	"/admin",
	"/api",
	"/app",
	"/dashboard",
	"/login",
	"/wp-admin",
	"/config.php",
	"/index.php",
	"/application.yml",
}

func pathsForScanner(name string, allPaths []string) []string {
	if fullPathScanners[name] {
		return allPaths
	}
	return entryPaths
}

func (se *ScannerEngine) ScanTarget(target *Target, paths []string, tg *TargetGenerator) {
	// L4 banner grab: once per target
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

	// Pre-probe: quick check if target is alive
	probeURL := fmt.Sprintf("%s://%s:%d/", scheme, target.Host, target.Port)
	probe := utils.Fetch(se.client, probeURL, "HEAD", nil, 0, 0)
	if probe == nil {
		// Some servers reject HEAD, try GET
		probe = utils.Fetch(se.client, probeURL, "GET", nil, 0, 0)
		if probe == nil {
			return
		}
	}

	for _, entry := range se.scanners {
		sName := entry.name
		scanner := entry.scanner
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

			if cnt := se.scanCounts[sName]; cnt != nil {
				atomic.AddInt64(cnt, 1)
			}
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
					if se.Config.Verbose {
						log.Printf("[%s] %s -> %d secrets, %d targets",
							sName, result.URL, len(result.Secrets), len(result.NewTargets))
					}
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

// scanTask is a unit of work for the worker pool.
type scanTask struct {
	target *Target
	paths  []string
	tg     *TargetGenerator
}

func (se *ScannerEngine) Run(targets []*Target, paths []string, tg *TargetGenerator) {
	se.start = time.Now()
	se.count = 0

	// Estimate requests
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

	// Fixed worker pool instead of goroutine-per-target
	numWorkers := se.Config.MaxConcurrentReqs
	taskCh := make(chan scanTask, numWorkers*2)
	var wg sync.WaitGroup

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskCh {
				if se.isStopped() {
					continue // drain channel
				}
				se.ScanTarget(task.target, task.paths, task.tg)
			}
		}()
	}

	// Feed targets in batches, log progress between batches
	batchSize := 500
	batchStart := 0
	for i, t := range targets {
		if se.isStopped() {
			break
		}
		taskCh <- scanTask{target: t, paths: paths, tg: tg}

		// Log progress every batchSize targets submitted
		if (i+1)%batchSize == 0 || i == len(targets)-1 {
			// Wait for current batch to mostly drain by checking count
			end := i + 1
			for {
				pending := end - batchStart - int(atomic.LoadInt64(&se.count)-int64(batchStart))
				if pending < numWorkers || se.isStopped() {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

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
			batchStart = end

			// Chain new targets between batches
			if tg != nil {
				existing := make(map[string]bool)
				for _, et := range targets {
					existing[fmt.Sprintf("%s:%d", et.Host, et.Port)] = true
				}
				chainCount := 0
				for _, nt := range tg.GetTargets() {
					if nt.Priority > 0 && !existing[fmt.Sprintf("%s:%d", nt.Host, nt.Port)] {
						taskCh <- scanTask{target: nt, paths: paths, tg: tg}
						chainCount++
						if chainCount >= 100 {
							break
						}
					}
				}
				if chainCount > 0 {
					log.Printf("Chaining: %d new targets", chainCount)
				}
			}
		}
	}

	close(taskCh)
	wg.Wait()

	elapsed := time.Since(se.start).Seconds()
	c := atomic.LoadInt64(&se.count)
	rps := float64(0)
	if elapsed > 0 {
		rps = float64(c) / elapsed
	}
	// Per-scanner call counts
	var scanStats []string
	for name, cnt := range se.scanCounts {
		scanStats = append(scanStats, fmt.Sprintf("%s=%d", name, atomic.LoadInt64(cnt)))
	}
	log.Printf("Done: %d reqs in %.1fs (%.0f RPS) | Scanner calls: %s", c, elapsed, rps, strings.Join(scanStats, ", "))
}
