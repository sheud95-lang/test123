package scanners

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"reaper/internal/core"
	"reaper/internal/extractors"
	"reaper/internal/utils"
)

var jsLinkPats = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]+src=['"]([^'"]+\.js(?:\?[^'"]*)?)['"]\s*>`),
	regexp.MustCompile(`['"]([^'"]*\.(?:js|mjs|cjs)(?:\?[^'"]*)?)['"]`),
}
var jsDefaults = []string{
	"/main.js", "/app.js", "/bundle.js", "/vendor.js",
	"/config.js", "/settings.js", "/env.js",
	"/static/js/main.js", "/static/js/app.js",
	"/assets/js/app.js", "/dist/bundle.js",
	"/js/app.js", "/js/main.js",
}

type JSScanner struct{ WAFEvasion bool; MaxJSFiles int }

func (s *JSScanner) Name() string { return "js" }

func (s *JSScanner) Scan(client *http.Client, host string, port int, path string, isIP bool, scheme string) *core.ScanResult {
	if port == 80 { scheme = "http" }
	mx := s.MaxJSFiles; if mx <= 0 { mx = 50 }
	base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	page := base + path
	var h map[string]string
	if s.WAFEvasion { ch := ""; if !isIP { ch = host }; h = core.GenerateHeaders(ch) }
	resp := utils.Fetch(client, page, "GET", h, 2, 500_000_000)
	if resp == nil || resp.Status >= 400 { return nil }

	jsURLs := make(map[string]bool)
	for _, pat := range jsLinkPats {
		for _, m := range pat.FindAllStringSubmatch(resp.Body, -1) {
			if len(m) > 1 {
				ref := m[1]
				if strings.HasPrefix(ref, "http") { jsURLs[ref] = true } else if strings.HasPrefix(ref, "/") { jsURLs[base+ref] = true } else { jsURLs[base+"/"+ref] = true }
			}
		}
	}
	for _, jp := range jsDefaults { jsURLs[base+jp] = true }

	var allS []extractors.Secret; var allT []string; sc := 0
	for u := range jsURLs {
		if sc >= mx { break }
		jr := utils.Fetch(client, u, "GET", h, 2, 500_000_000)
		if jr == nil || jr.Status >= 400 || len(jr.Body) < 10 { continue }
		sc++
		allS = append(allS, extractors.ExtractSecrets(jr.Body, u)...)
		td := extractors.ExtractAllTargets(jr.Body, u)
		allT = append(allT, td.IPs...); allT = append(allT, td.Domains...)
	}
	if len(allS) > 0 || len(allT) > 0 {
		return &core.ScanResult{URL: page, Status: resp.Status, Scanner: s.Name(), Secrets: allS, NewTargets: uniqueStrings(allT), ResponseSize: resp.Size}
	}
	return nil
}
