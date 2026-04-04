package core

import (
	"fmt"
	"sync"

	"reaper/internal/utils"
)

type Target struct {
	Host     string
	Port     int
	IsIP     bool
	Source   string
	Priority int
}

type TargetGenerator struct {
	mu             sync.Mutex
	targets        map[string]*Target
	excludePrivate bool
	blacklist      map[string]bool
	maxTargets     int
	fromParse      int
}

func NewTargetGenerator(excludePrivate bool, bl map[string]bool, max int) *TargetGenerator {
	if bl == nil {
		bl = make(map[string]bool)
	}
	return &TargetGenerator{targets: make(map[string]*Target), excludePrivate: excludePrivate, blacklist: bl, maxTargets: max}
}

func (tg *TargetGenerator) AddFromParsedContent(text string, ports []int) {
	if ports == nil {
		ports = []int{80, 443}
	}
	filtered := utils.FilterIPs(utils.ExtractIPsFromText(text), tg.excludePrivate, tg.blacklist)
	tg.mu.Lock()
	defer tg.mu.Unlock()
	for _, ip := range filtered {
		for _, port := range ports {
			key := fmt.Sprintf("%s:%d", ip, port)
			if _, ok := tg.targets[key]; !ok && len(tg.targets) < tg.maxTargets {
				tg.targets[key] = &Target{Host: ip, Port: port, IsIP: true, Source: "content_parse", Priority: 1}
				tg.fromParse++
			}
		}
	}
}

func (tg *TargetGenerator) GetTargets() []*Target {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	out := make([]*Target, 0, len(tg.targets))
	for _, t := range tg.targets {
		out = append(out, t)
	}
	return out
}

func (tg *TargetGenerator) Stats() map[string]int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return map[string]int{"from_parse": tg.fromParse, "total": len(tg.targets)}
}
