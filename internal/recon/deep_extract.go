package recon

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	// HTML tag attributes that contain URLs
	htmlURLRe = regexp.MustCompile(`(?i)(?:href|src|action|data-src|data-url|data-href|poster|srcset)\s*=\s*["']([^"']+)["']`)
	// Inline script content
	scriptBlockRe = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
	// Source map references
	sourceMapRe = regexp.MustCompile(`//[#@]\s*sourceMappingURL=(\S+)`)
	// JS import/require
	jsImportRe = regexp.MustCompile(`(?:import\s.*?from\s+|require\s*\(\s*)['"]([^'"]+)['"]`)
	// API/fetch patterns (deeper than link_parser)
	deepFetchRe = regexp.MustCompile(`(?i)(?:fetch|axios|XMLHttpRequest|\.open)\s*\(\s*['"\x60]([^'"\x60\s]{5,})['"\x60]`)
	// Config/endpoint objects
	configURLRe = regexp.MustCompile(`(?i)(?:baseURL|apiUrl|API_BASE|endpoint|server|host|backend|gateway)\s*[=:]\s*['"\x60](https?://[^'"\x60\s]+)['"\x60]`)
	// robots.txt / sitemap patterns
	sitemapURLRe = regexp.MustCompile(`(?i)(?:Sitemap|Allow|Disallow):\s*(\S+)`)
)

// doDeepExtract fetches a URL and extracts all possible targets from the content
func (re *ReconEngine) doDeepExtract(targetURL string, ports []int) int {
	resp, err := re.client.Get(targetURL)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil || resp.StatusCode >= 400 {
		return 0
	}

	content := string(body)
	count := 0
	seen := make(map[string]bool)

	baseURL, _ := url.Parse(targetURL)

	// 1. Extract all HTML attribute URLs
	for _, m := range htmlURLRe.FindAllStringSubmatch(content, -1) {
		u := m[1]
		if resolved := resolveURL(baseURL, u); resolved != "" && !seen[resolved] {
			seen[resolved] = true
			count++
		}
	}

	// 2. Extract from inline scripts
	for _, m := range scriptBlockRe.FindAllStringSubmatch(content, -1) {
		script := m[1]
		count += re.extractFromJS(script, baseURL, seen)
	}

	// 3. Source maps
	for _, m := range sourceMapRe.FindAllStringSubmatch(content, -1) {
		mapURL := resolveURL(baseURL, m[1])
		if mapURL != "" {
			count += re.fetchAndParseSourceMap(mapURL, seen)
		}
	}

	// 4. Try fetching common discovery files
	discoveryPaths := []string{"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}
	host := baseURL.Scheme + "://" + baseURL.Host
	for _, p := range discoveryPaths {
		dURL := host + p
		if seen[dURL] {
			continue
		}
		seen[dURL] = true
		count += re.fetchDiscoveryFile(dURL, baseURL, seen)
	}

	// Add all discovered URLs/domains as targets
	if count > 0 {
		var targets strings.Builder
		for u := range seen {
			if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
				targets.WriteString(parsed.Host + "\n")
			}
		}
		if targets.Len() > 0 {
			re.tg.AddFromParsedContent(targets.String(), ports)
		}
	}

	return count
}

func (re *ReconEngine) extractFromJS(script string, baseURL *url.URL, seen map[string]bool) int {
	count := 0
	for _, re := range []*regexp.Regexp{deepFetchRe, configURLRe, jsImportRe} {
		for _, m := range re.FindAllStringSubmatch(script, -1) {
			u := m[1]
			if resolved := resolveURL(baseURL, u); resolved != "" && !seen[resolved] {
				seen[resolved] = true
				count++
			}
		}
	}
	return count
}

func (re *ReconEngine) fetchAndParseSourceMap(mapURL string, seen map[string]bool) int {
	resp, err := re.client.Get(mapURL)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil || resp.StatusCode != http.StatusOK {
		return 0
	}

	var sm struct {
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
	}
	if json.Unmarshal(body, &sm) != nil {
		return 0
	}

	count := 0
	baseURL, _ := url.Parse(mapURL)

	// Extract domains from source paths
	for _, src := range sm.Sources {
		if resolved := resolveURL(baseURL, src); resolved != "" && !seen[resolved] {
			seen[resolved] = true
			count++
		}
	}

	// Scan source content for URLs
	for _, content := range sm.SourcesContent {
		count += re.extractFromJS(content, baseURL, seen)
	}
	return count
}

func (re *ReconEngine) fetchDiscoveryFile(fileURL string, baseURL *url.URL, seen map[string]bool) int {
	resp, err := re.client.Get(fileURL)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil || resp.StatusCode != http.StatusOK {
		return 0
	}

	content := string(body)
	count := 0

	for _, m := range sitemapURLRe.FindAllStringSubmatch(content, -1) {
		u := m[1]
		if resolved := resolveURL(baseURL, u); resolved != "" && !seen[resolved] {
			seen[resolved] = true
			count++
		}
	}
	return count
}

func resolveURL(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "#" || raw == "/" || strings.HasPrefix(raw, "javascript:") ||
		strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "mailto:") {
		return ""
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	if parsed.IsAbs() {
		if parsed.Scheme == "http" || parsed.Scheme == "https" {
			return parsed.String()
		}
		return ""
	}

	if base != nil {
		resolved := base.ResolveReference(parsed)
		return resolved.String()
	}
	return ""
}
