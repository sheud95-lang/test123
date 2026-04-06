package recon

import (
	"strings"

	"reaper/internal/utils"
)

var commonTLDs = []string{
	".com", ".net", ".org", ".io", ".dev", ".co", ".app", ".xyz",
	".info", ".biz", ".us", ".uk", ".eu", ".ru", ".de", ".fr",
	".ca", ".au", ".in", ".br", ".jp", ".cn", ".kr",
}

// doTLDSweep tries the base domain name with different TLDs
func (re *ReconEngine) doTLDSweep(domain string, ports []int) int {
	base := extractBaseName(domain)
	if base == "" {
		return 0
	}

	count := 0
	for _, tld := range commonTLDs {
		candidate := base + tld
		if candidate == domain {
			continue
		}
		ips := utils.ResolveDomain(candidate)
		if len(ips) == 0 {
			continue
		}
		re.tg.AddFromParsedContent(candidate+"\n", ports)
		count++
	}
	return count
}

// extractBaseName strips the TLD from a domain: "example.com" -> "example"
func extractBaseName(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	// Handle two-part TLDs like .co.uk
	if len(parts) >= 3 {
		second := parts[len(parts)-2]
		if second == "co" || second == "com" || second == "org" || second == "net" || second == "ac" || second == "gov" {
			if len(parts) >= 3 {
				return strings.Join(parts[:len(parts)-2], ".")
			}
		}
	}
	return strings.Join(parts[:len(parts)-1], ".")
}
