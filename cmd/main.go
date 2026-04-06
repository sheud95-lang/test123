package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"reaper/internal/config"
	"reaper/internal/engine"
)

func banner(cfg *config.ScanConfig, wlCount int) {
	fmt.Println(`
    ____
   / __ \___  ____ _____  ___  _____
  / /_/ / _ \/ __ ` + "`" + `/ __ \/ _ \/ ___/
 / _, _/  __/ /_/ / /_/ /  __/ /
/_/ |_|\___/\__,_/ .___/\___/_/   v3-go
                /_/
    Zero-Target Secret Scanner
    `)
	wlLabel := "default"
	if wlCount > 0 {
		wlLabel = strconv.Itoa(wlCount)
	}
	fmt.Printf("  Wordlists:   %s\n", wlLabel)
	fmt.Printf("  Max targets: %d\n", cfg.MaxTargets)
	fmt.Printf("  Mode:        %s | %s\n", cfg.TargetMode, cfg.ScanMode)
	fmt.Printf("  Ports:       %v\n", cfg.Ports)
	fmt.Printf("  RPS:         %d\n", cfg.TargetRPS)
	fmt.Printf("  Scanners:    %s\n", strings.Join(cfg.EnabledScanners, ", "))
	wafLabel := "ON"
	if !cfg.WAFEvasion {
		wafLabel = "OFF"
	}
	fmt.Printf("  WAF bypass:  %s\n", wafLabel)
	fmt.Printf("  Output:      %s/\n\n", cfg.OutputDir)
}

func parsePorts(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		if v, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			ports = append(ports, v)
		}
	}
	return ports
}

func main() {
	var (
		wordlists       string
		noDefaultPaths  bool
		maxTargets      int
		targetMode      string
		noPrecheck      bool
		precheckTimeout float64
		precheckConc    int
		portsStr        string
		scanMode        string
		rps             int
		concurrency     int
		scannersStr     string
		noWAF           bool
		wafLevel        int
		connectTimeout  float64
		readTimeout     float64
		outputDir       string
		quiet           bool
		validate        bool
		recon           bool
		reconReverseIP  bool
		reconSubdomains bool
		reconTLD        bool
		reconDeep       bool
	)

	flag.StringVar(&wordlists, "w", "", "Comma-separated wordlist files")
	flag.BoolVar(&noDefaultPaths, "no-default-paths", false, "Skip built-in paths")
	flag.IntVar(&maxTargets, "max-targets", 50000, "Max targets")
	flag.StringVar(&targetMode, "target-mode", "all", "random, ranges, api, all")
	flag.BoolVar(&noPrecheck, "no-precheck", false, "Skip port precheck")
	flag.Float64Var(&precheckTimeout, "precheck-timeout", 2.0, "Precheck timeout")
	flag.IntVar(&precheckConc, "precheck-concurrency", 5000, "Precheck concurrency")
	flag.StringVar(&portsStr, "ports", "80,443,8080,8443", "Ports")
	flag.StringVar(&scanMode, "mode", "L4+L7", "L4, L7, L4+L7")
	flag.IntVar(&rps, "rps", 4000, "RPS")
	flag.IntVar(&concurrency, "concurrency", 800, "Concurrency")
	flag.StringVar(&scannersStr, "scanners", "path,js,r2s,nvca,ajs,uafr,git", "Scanners")
	flag.BoolVar(&noWAF, "no-waf-bypass", false, "Disable WAF evasion")
	flag.IntVar(&wafLevel, "waf-level", 1, "WAF bypass level 1-5 (5=adaptive)")
	flag.Float64Var(&connectTimeout, "connect-timeout", 5.0, "Connect timeout")
	flag.Float64Var(&readTimeout, "read-timeout", 8.0, "Read timeout")
	flag.StringVar(&outputDir, "o", "results", "Output dir")
	flag.BoolVar(&quiet, "q", false, "Quiet")
	flag.BoolVar(&validate, "validate", false, "Validate found secrets against APIs")
	flag.BoolVar(&recon, "recon", false, "Enable all recon modules")
	flag.BoolVar(&reconReverseIP, "recon-reverse-ip", false, "Enable reverse IP lookup")
	flag.BoolVar(&reconSubdomains, "recon-subdomains", false, "Enable subdomain enumeration")
	flag.BoolVar(&reconTLD, "recon-tld", false, "Enable TLD sweep")
	flag.BoolVar(&reconDeep, "recon-deep", false, "Enable deep JS/HTML chaining")
	flag.Parse()

	scannersList := strings.Split(scannersStr, ",")
	for i := range scannersList {
		scannersList[i] = strings.TrimSpace(scannersList[i])
	}

	cfg := &config.ScanConfig{
		MaxTargets:          maxTargets,
		TargetMode:          targetMode,
		Ports:               parsePorts(portsStr),
		PrecheckPorts:       !noPrecheck,
		PrecheckTimeout:     time.Duration(precheckTimeout * float64(time.Second)),
		PrecheckConcurrency: precheckConc,
		ShodanAPIKey:        os.Getenv("SHODAN_API_KEY"),
		CensysAPIID:         os.Getenv("CENSYS_API_ID"),
		CensysAPISecret:     os.Getenv("CENSYS_API_SECRET"),
		FOFAEmail:           os.Getenv("FOFA_EMAIL"),
		FOFAAPIKey:          os.Getenv("FOFA_API_KEY"),
		MaxConcurrentReqs:   concurrency,
		MaxConnsPerHost:     15,
		TotalConnectorLimit: 2000,
		TargetRPS:           rps,
		BurstSize:           500,
		ConnectTimeout:      time.Duration(connectTimeout * float64(time.Second)),
		ReadTimeout:         time.Duration(readTimeout * float64(time.Second)),
		TotalTimeout:        12 * time.Second,
		ScanMode:            scanMode,
		WAFEvasion:          !noWAF,
		WAFLevel:            wafLevel,
		DelayJitterMinMs:    0,
		DelayJitterMaxMs:    30,
		EnabledScanners:     scannersList,
		OutputDir:           outputDir,
		Verbose:             !quiet,
		ExcludePrivate:      true,
		Validate:            validate,
		Recon:               recon,
		ReconReverseIP:      recon || reconReverseIP,
		ReconSubdomains:     recon || reconSubdomains,
		ReconTLDSweep:       recon || reconTLD,
		ReconDeepChain:      recon || reconDeep,
		AutosaveInterval:    30 * time.Second,
	}

	os.MkdirAll(cfg.OutputDir, 0o755)
	if cfg.Verbose {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(os.NewFile(0, os.DevNull))
	}

	var wlFiles []string
	if wordlists != "" {
		wlFiles = strings.Split(wordlists, ",")
		for i := range wlFiles {
			wlFiles[i] = strings.TrimSpace(wlFiles[i])
		}
	}

	banner(cfg, len(wlFiles))

	eng := engine.NewReaperEngine(cfg)
	if err := eng.Run(wlFiles, noDefaultPaths); err != nil {
		log.Fatalf("Error: %v", err)
	}
}