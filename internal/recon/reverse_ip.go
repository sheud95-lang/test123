package recon

import (
	"io"
	"net/http"
	"strings"
)

// doReverseIP queries HackerTarget API for domains on the given IP
func (re *ReconEngine) doReverseIP(ip string, ports []int) int {
	resp, err := re.client.Get("https://api.hackertarget.com/reverseiplookup/?q=" + ip)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil || resp.StatusCode != http.StatusOK {
		return 0
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) == 0 || strings.Contains(lines[0], "error") || strings.Contains(lines[0], "API count") {
		return 0
	}

	count := 0
	for _, domain := range lines {
		domain = strings.TrimSpace(domain)
		if domain == "" || strings.Contains(domain, " ") {
			continue
		}
		// Add each domain as a new target
		targets := domain + "\n"
		re.tg.AddFromParsedContent(targets, ports)
		count++
	}
	return count
}
