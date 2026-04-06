package extractors

import (
	"net/url"
	"regexp"
	"strings"

	"reaper/internal/utils"
)

var (
	urlPattern          = regexp.MustCompile(`https?://[^\s<>"'` + "`" + `\)}\]]+`)
	relativePathPattern = regexp.MustCompile(`['"](/[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)['"]`)
	domainPattern       = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	endpointPattern     = regexp.MustCompile(`(?i)(?:fetch|axios|\.get|\.post|\.put|\.delete|url|href|src|action|endpoint|api[_-]?(?:url|endpoint|base))\s*[\(=:]\s*['"\x60]([^'"\x60\s]+)['"\x60]`)
)

var staticExts = map[string]bool{
	".css": true, ".png": true, ".jpg": true,
	".gif": true, ".svg": true, ".woff": true, ".woff2": true, ".ttf": true,
}

func ExtractURLs(text, baseURL string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, m := range urlPattern.FindAllString(text, -1) {
		m = strings.TrimRight(m, ".,;:!?)}>]'\"")
		if !seen[m] {
			seen[m] = true
			result = append(result, m)
		}
	}
	if baseURL != "" {
		base, err := url.Parse(baseURL)
		if err == nil {
			for _, ms := range relativePathPattern.FindAllStringSubmatch(text, -1) {
				if len(ms) > 1 {
					if ref, err := url.Parse(ms[1]); err == nil {
						r := base.ResolveReference(ref).String()
						if !seen[r] {
							seen[r] = true
							result = append(result, r)
						}
					}
				}
			}
			for _, ms := range endpointPattern.FindAllStringSubmatch(text, -1) {
				if len(ms) > 1 {
					ep := ms[1]
					if strings.HasPrefix(ep, "http") {
						if !seen[ep] {
							seen[ep] = true
							result = append(result, ep)
						}
					} else if strings.HasPrefix(ep, "/") {
						if ref, err := url.Parse(ep); err == nil {
							r := base.ResolveReference(ref).String()
							if !seen[r] {
								seen[r] = true
								result = append(result, r)
							}
						}
					}
				}
			}
		}
	}
	return result
}

func ExtractDomains(text string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, m := range domainPattern.FindAllString(text, -1) {
		d := strings.ToLower(m)
		lastDot := strings.LastIndex(d, ".")
		if lastDot > 0 && staticExts[d[lastDot:]] {
			continue
		}
		if !seen[d] {
			seen[d] = true
			result = append(result, d)
		}
	}
	return result
}

type TargetsFound struct {
	URLs    []string
	IPs     []string
	Domains []string
}

func ExtractAllTargets(text, baseURL string) TargetsFound {
	return TargetsFound{
		URLs:    ExtractURLs(text, baseURL),
		IPs:     utils.ExtractIPsFromText(text),
		Domains: ExtractDomains(text),
	}
}
