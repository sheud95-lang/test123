package recon

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"reaper/internal/utils"
)

// doSubdomainEnum performs passive + active subdomain enumeration
func (re *ReconEngine) doSubdomainEnum(domain string, ports []int) int {
	seen := make(map[string]bool)
	count := 0

	// 1. Passive: crt.sh certificate transparency
	crtDomains := re.queryCrtSh(domain)
	for _, d := range crtDomains {
		d = strings.TrimPrefix(d, "*.")
		if d != "" && !seen[d] {
			seen[d] = true
			re.tg.AddFromParsedContent(d+"\n", ports)
			count++
		}
	}

	// 2. Active: DNS bruteforce using existing utility
	results := utils.EnumerateSubdomains(domain, nil)
	for _, r := range results {
		if !seen[r.Subdomain] && len(r.IPs) > 0 {
			seen[r.Subdomain] = true
			re.tg.AddFromParsedContent(r.Subdomain+"\n", ports)
			count++
		}
	}

	return count
}

func (re *ReconEngine) queryCrtSh(domain string) []string {
	url := "https://crt.sh/?q=%25." + domain + "&output=json"
	resp, err := re.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal(body, &entries) != nil {
		return nil
	}

	seen := make(map[string]bool)
	var domains []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.TrimPrefix(name, "*."))
			if name != "" && !seen[name] {
				seen[name] = true
				domains = append(domains, name)
			}
		}
	}
	return domains
}
