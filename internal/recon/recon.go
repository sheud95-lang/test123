package recon

import (
	"crypto/tls"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"reaper/internal/config"
	"reaper/internal/core"
)

type reconTask struct {
	taskType string // "reverse_ip", "subdomain", "tld", "deep"
	target   string // IP, domain, or URL
	ports    []int
}

type ReconEngine struct {
	client *http.Client
	tg     *core.TargetGenerator
	cfg    *config.ScanConfig
	seen    sync.Map    // dedup: already processed targets
	queue   chan reconTask
	stop    chan struct{}
	wg      sync.WaitGroup
	sem     chan struct{} // concurrency limiter
	stopped int32        // atomic: 1 = stopped
}

func NewReconEngine(cfg *config.ScanConfig, tg *core.TargetGenerator) *ReconEngine {
	return &ReconEngine{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        30,
				MaxIdleConnsPerHost: 5,
			},
		},
		tg:    tg,
		cfg:   cfg,
		queue: make(chan reconTask, 5000),
		stop:  make(chan struct{}),
		sem:   make(chan struct{}, 20),
	}
}

func (re *ReconEngine) Run() {
	for {
		select {
		case task := <-re.queue:
			re.wg.Add(1)
			re.sem <- struct{}{}
			go func(t reconTask) {
				defer re.wg.Done()
				defer func() { <-re.sem }()
				re.processTask(t)
			}(task)
		case <-re.stop:
			// Drain remaining tasks without closing the channel
			// (other goroutines may still send)
		drain:
			for {
				select {
				case task := <-re.queue:
					re.processTask(task)
				default:
					break drain
				}
			}
			re.wg.Wait()
			return
		}
	}
}

func (re *ReconEngine) Stop() {
	atomic.StoreInt32(&re.stopped, 1)
	close(re.stop)
	re.wg.Wait()
}

// SubmitIP submits an IP for reverse lookup
func (re *ReconEngine) SubmitIP(ip string) {
	if atomic.LoadInt32(&re.stopped) != 0 || !re.cfg.ReconReverseIP {
		return
	}
	if _, loaded := re.seen.LoadOrStore("rip:"+ip, true); loaded {
		return
	}
	select {
	case re.queue <- reconTask{taskType: "reverse_ip", target: ip, ports: re.cfg.Ports}:
	default:
	}
}

// SubmitDomain submits a domain for subdomain enum + TLD sweep
func (re *ReconEngine) SubmitDomain(domain string) {
	if atomic.LoadInt32(&re.stopped) != 0 {
		return
	}
	if _, loaded := re.seen.LoadOrStore("dom:"+domain, true); loaded {
		return
	}
	if re.cfg.ReconSubdomains {
		select {
		case re.queue <- reconTask{taskType: "subdomain", target: domain, ports: re.cfg.Ports}:
		default:
		}
	}
	if re.cfg.ReconTLDSweep {
		select {
		case re.queue <- reconTask{taskType: "tld", target: domain, ports: re.cfg.Ports}:
		default:
		}
	}
}

// SubmitURL submits a URL for deep content extraction
func (re *ReconEngine) SubmitURL(u string) {
	if atomic.LoadInt32(&re.stopped) != 0 || !re.cfg.ReconDeepChain {
		return
	}
	if _, loaded := re.seen.LoadOrStore("url:"+u, true); loaded {
		return
	}
	select {
	case re.queue <- reconTask{taskType: "deep", target: u, ports: re.cfg.Ports}:
	default:
	}
}

func (re *ReconEngine) processTask(task reconTask) {
	var count int
	switch task.taskType {
	case "reverse_ip":
		count = re.doReverseIP(task.target, task.ports)
	case "subdomain":
		count = re.doSubdomainEnum(task.target, task.ports)
	case "tld":
		count = re.doTLDSweep(task.target, task.ports)
	case "deep":
		count = re.doDeepExtract(task.target, task.ports)
	}
	if count > 0 {
		log.Printf("[RECON] %s %s: +%d targets", task.taskType, task.target, count)
	}
}
