package config

import "time"

type ScanConfig struct {
	MaxTargets          int
	TargetMode          string
	Ports               []int
	PrecheckPorts       bool
	PrecheckTimeout     time.Duration
	PrecheckConcurrency int
	ShodanAPIKey        string
	CensysAPIID         string
	CensysAPISecret     string
	FOFAEmail           string
	FOFAAPIKey          string
	MaxConcurrentReqs   int
	MaxConnsPerHost     int
	TotalConnectorLimit int
	TargetRPS           int
	BurstSize           int
	ConnectTimeout      time.Duration
	ReadTimeout         time.Duration
	TotalTimeout        time.Duration
	ScanMode            string
	WAFEvasion          bool
	WAFLevel            int // 1-5, default 1
	DelayJitterMinMs    int
	DelayJitterMaxMs    int
	EnabledScanners     []string
	OutputDir           string
	Verbose             bool
	ExcludePrivate      bool
	BlacklistFile       string
	Validate            bool
	Recon               bool
	ReconReverseIP      bool
	ReconSubdomains     bool
	ReconTLDSweep       bool
	ReconDeepChain      bool
	AutosaveInterval    time.Duration
}