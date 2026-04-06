package engine

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"reaper/internal/config"
	"reaper/internal/core"
	"reaper/internal/scanners"
	"reaper/internal/validators"
)

type ReaperEngine struct {
	Config   *config.ScanConfig
	PL       *core.PathLoader
	RS       *core.ResultStore
	IPGen    *core.IPGenerator
	TG       *core.TargetGenerator
	SE       *core.ScannerEngine
	Treasure *core.TreasureWriter
	Dedup    *core.DedupStore
}

func NewReaperEngine(cfg *config.ScanConfig) *ReaperEngine {
	os.MkdirAll(cfg.OutputDir, 0o755)
	rs := core.NewResultStore(cfg.OutputDir)
	tg := core.NewTargetGenerator(cfg.ExcludePrivate, nil, cfg.MaxTargets)
	tw := core.NewTreasureWriter(cfg.OutputDir)
	se := core.NewScannerEngine(cfg, rs, tw)
	dedup := core.NewDedupStore(cfg.OutputDir)

	waf := cfg.WAFEvasion
	sm := map[string]core.Scanner{
		"path": &scanners.PathScanner{WAFEvasion: waf},
		"js":   &scanners.JSScanner{WAFEvasion: waf, MaxJSFiles: 50},
		"r2s":  &scanners.R2SScanner{WAFEvasion: waf},
		"nvca": &scanners.NVCAScanner{WAFEvasion: waf},
		"ajs":  &scanners.AJSScanner{WAFEvasion: waf, MaxEndpoints: 100},
		"uafr": &scanners.UAFRScanner{WAFEvasion: waf},
		"git":  &scanners.GitScanner{WAFEvasion: waf, MaxObjects: 50},
	}
	for _, name := range cfg.EnabledScanners {
		if s, ok := sm[name]; ok {
			se.RegisterScanner(s)
		}
	}

	// Validation pipeline (optional)
	if cfg.Validate {
		v := validators.NewValidator(tw)
		se.Validator = v
		go v.Run()
		log.Printf("Secret validation: ENABLED")
	}

	return &ReaperEngine{
		Config: cfg, PL: core.NewPathLoader(), RS: rs,
		IPGen: core.NewIPGenerator(cfg), TG: tg, SE: se,
		Treasure: tw, Dedup: dedup,
	}
}

func (e *ReaperEngine) Run(wlFiles []string, noDefault bool) error {
	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Ctrl+C — saving results...")
		e.SE.Stop()
		e.save()
		fmt.Printf("Stats: %s\n", e.SE.ScannerStats())
		fmt.Println(e.RS.Summary())
		fmt.Printf("[+] Results saved to %s/\n", e.Config.OutputDir)
		os.Exit(0)
	}()

	if !noDefault {
		log.Printf("Default paths: %d", e.PL.LoadDefault())
	}
	for _, wf := range wlFiles {
		c, err := e.PL.LoadFile(wf)
		if err != nil {
			log.Printf("Warning: %s: %v", wf, err)
			continue
		}
		log.Printf("Wordlist '%s': %d paths", wf, c)
	}
	paths := e.PL.GetAllPaths()
	if len(paths) == 0 {
		return fmt.Errorf("no paths loaded")
	}
	log.Printf("Total paths: %d", len(paths))
	log.Printf("Dedup store: %d previously seen URLs", e.Dedup.Count())

	alive, err := e.IPGen.Generate(context.Background())
	if err != nil {
		return err
	}
	if len(alive) == 0 {
		return fmt.Errorf("no alive targets")
	}

	// Filter out previously seen targets
	var targets []*core.Target
	for _, hp := range alive {
		key := fmt.Sprintf("%s:%d", hp.Host, hp.Port)
		if !e.Dedup.IsSeen(key) {
			e.Dedup.MarkSeen(key)
			targets = append(targets, &core.Target{Host: hp.Host, Port: hp.Port, IsIP: true, Source: "auto"})
		}
	}
	log.Printf("Targets: %d (gen %d, alive %d, after dedup %d)",
		len(targets), len(e.IPGen.Generated), len(e.IPGen.Alive), len(targets))

	if len(targets) == 0 {
		log.Printf("All targets already seen. Increase --max-targets or delete %s/.seen_urls", e.Config.OutputDir)
		return nil
	}

	// Autosave
	interval := e.Config.AutosaveInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	e.RS.StartAutosave(interval)
	log.Printf("Autosave every %s", interval)

	e.SE.Run(targets, paths, e.TG)
	e.RS.StopAutosave()
	e.save()

	fmt.Println()
	fmt.Println(e.RS.Summary())
	fmt.Printf("\nResults: %s/\n", e.Config.OutputDir)
	fmt.Printf("  results.json\n")
	fmt.Printf("  results.csv\n")
	fmt.Printf("  hits_live.txt\n")
	fmt.Printf("  treasure/\n")

	tStats := e.Treasure.GetStats()
	type kv struct {
		K string
		V int
	}
	var sorted []kv
	for k, v := range tStats {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].V > sorted[j].V })
	for _, item := range sorted {
		fmt.Printf("    %s.txt: %d\n", item.K, item.V)
	}
	fmt.Printf("    all.txt\n")
	fmt.Printf("    all_valid.txt\n")

	return nil
}

func (e *ReaperEngine) save() {
	// Stop validator first so it finishes pending validations before treasure closes
	if v, ok := e.SE.Validator.(*validators.Validator); ok && v != nil {
		v.Stop()
	}
	e.RS.SaveNow()
	e.Treasure.Close()
	e.Dedup.Save()
}