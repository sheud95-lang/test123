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
	DelayJitterMinMs    int
	DelayJitterMaxMs    int
	EnabledScanners     []string
	OutputDir           string
	Verbose             bool
	ExcludePrivate      bool
	BlacklistFile       string
	Validate            bool
	AutosaveInterval    time.Duration
}