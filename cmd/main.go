package main

import (
	"bufio"
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
	fmt.Printf("  WAF bypass:  %s (L%d)\n", wafLabel, cfg.WAFLevel)
	if cfg.Validate {
		fmt.Printf("  Validation:  ON\n")
	}
	if cfg.Recon || cfg.ReconReverseIP || cfg.ReconSubdomains || cfg.ReconTLDSweep || cfg.ReconDeepChain {
		fmt.Printf("  Recon:       ON\n")
	}
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

func readLine(prompt string) string {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func readIntDefault(prompt string, def int) int {
	s := readLine(fmt.Sprintf("%s [%d]: ", prompt, def))
	if s == "" {
		return def
	}
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

func interactiveMenu() (*config.ScanConfig, string) {
	fmt.Println(`
    ____
   / __ \___  ____ _____  ___  _____
  / /_/ / _ \/ __ ` + "`" + `/ __ \/ _ \/ ___/
 / _, _/  __/ /_/ / /_/ /  __/ /
/_/ |_|\___/\__,_/ .___/\___/_/   v3-go
                /_/
    Zero-Target Secret Scanner`)
	fmt.Println()

	cfg := &config.ScanConfig{
		MaxTargets:          50000,
		TargetMode:          "all",
		Ports:               []int{80, 443, 8080, 8443},
		PrecheckPorts:       true,
		PrecheckTimeout:     2 * time.Second,
		PrecheckConcurrency: 5000,
		ShodanAPIKey:        os.Getenv("SHODAN_API_KEY"),
		CensysAPIID:         os.Getenv("CENSYS_API_ID"),
		CensysAPISecret:     os.Getenv("CENSYS_API_SECRET"),
		FOFAEmail:           os.Getenv("FOFA_EMAIL"),
		FOFAAPIKey:          os.Getenv("FOFA_API_KEY"),
		MaxConcurrentReqs:   800,
		MaxConnsPerHost:     15,
		TotalConnectorLimit: 2000,
		TargetRPS:           4000,
		BurstSize:           500,
		ConnectTimeout:      5 * time.Second,
		ReadTimeout:         8 * time.Second,
		TotalTimeout:        12 * time.Second,
		ScanMode:            "L4+L7",
		WAFEvasion:          true,
		WAFLevel:            1,
		DelayJitterMinMs:    0,
		DelayJitterMaxMs:    30,
		EnabledScanners:     []string{"path", "js", "r2s", "nvca", "ajs", "uafr", "git"},
		OutputDir:           "results",
		Verbose:             true,
		ExcludePrivate:      true,
		AutosaveInterval:    30 * time.Second,
	}

	// Auto-detect paths.txt in current directory
	pathsFile := ""
	if _, err := os.Stat("paths.txt"); err == nil {
		fmt.Println("  [*] Found paths.txt in current directory")
		pathsFile = "paths.txt"
	}

	// Paths file prompt
	pathsIn := readLine(fmt.Sprintf("  Paths file [%s]: ", pathsFile))
	if pathsIn != "" {
		pathsFile = pathsIn
	}

	cfg.MaxTargets = readIntDefault("  Max targets", 50000)
	cfg.TargetRPS = readIntDefault("  RPS", 4000)
	cfg.MaxConcurrentReqs = readIntDefault("  Concurrency", 800)

	portsIn := readLine("  Ports [80,443,8080,8443]: ")
	if portsIn != "" {
		cfg.Ports = parsePorts(portsIn)
	}

	modeIn := readLine("  Mode (L4, L7, L4+L7) [L4+L7]: ")
	if modeIn != "" {
		cfg.ScanMode = modeIn
	}

	scannersIn := readLine("  Scanners [path,js,r2s,nvca,ajs,uafr,git]: ")
	if scannersIn != "" {
		list := strings.Split(scannersIn, ",")
		for i := range list {
			list[i] = strings.TrimSpace(list[i])
		}
		cfg.EnabledScanners = list
	}

	cfg.WAFLevel = readIntDefault("  WAF level (0=off, 1-5)", 1)
	cfg.WAFEvasion = cfg.WAFLevel > 0

	validateIn := readLine("  Validate secrets? (y/N): ")
	cfg.Validate = strings.ToLower(validateIn) == "y"

	reconIn := readLine("  Enable recon? (y/N): ")
	if strings.ToLower(reconIn) == "y" {
		cfg.Recon = true
		cfg.ReconReverseIP = true
		cfg.ReconSubdomains = true
		cfg.ReconTLDSweep = true
		cfg.ReconDeepChain = true
	}

	outIn := readLine("  Output dir [results]: ")
	if outIn != "" {
		cfg.OutputDir = outIn
	}

	return cfg, pathsFile
}

func main() {
	// Interactive mode: no args → configure and run
	if len(os.Args) == 1 {
		cfg, pathsFile := interactiveMenu()
		fmt.Println()

		os.MkdirAll(cfg.OutputDir, 0o755)
		log.SetOutput(os.Stdout)

		var wlFiles []string
		if pathsFile != "" {
			wlFiles = []string{pathsFile}
		}

		banner(cfg, len(wlFiles))

		eng := engine.NewReaperEngine(cfg)
		if err := eng.Run(wlFiles, false); err != nil {
			log.Fatalf("Error: %v", err)
		}
		return
	}

	// Flag-based mode for advanced users / automation
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
