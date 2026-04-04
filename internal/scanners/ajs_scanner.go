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

var (
	apiEPRe     = regexp.MustCompile(`(?i)['"\x60](/(?:api|v[0-9]+|graphql|rest|internal|backend|service|auth|oauth|webhook)[^\s'"\x60]{2,})['"\x60]`)
	fetchRe     = regexp.MustCompile(`(?i)(?:fetch|axios\.\w+|this\.\$http\.\w+|\$\.(?:get|post|ajax))\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]`)
	cfgRe       = regexp.MustCompile(`(?i)(?:baseURL|apiUrl|API_URL|API_BASE|BACKEND_URL|BASE_URL|endpoint)\s*[=:]\s*['"\x60]([^'"\x60]+)['"\x60]`)
	sSrcRe      = regexp.MustCompile(`(?i)<script[^>]+src=['"]([^'"]+\.js[^'"]*)['"]`)
)

type AJSScanner struct{ WAFEvasion bool; MaxEndpoints int }

func (s *AJSScanner) Name() string { return "ajs" }

func (s *AJSScanner) Scan(client *http.Client, host string, port int, path string, isIP bool, scheme string) *core.ScanResult {
	if port == 80 { scheme = "http" }
	mx := s.MaxEndpoints; if mx <= 0 { mx = 100 }
	base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	page := base + path
	var h map[string]string
	if s.WAFEvasion { ch := ""; if !isIP { ch = host }; h = core.GenerateHeaders(ch) }
	resp := utils.Fetch(client, page, "GET", h, 2, 500_000_000)
	if resp == nil || resp.Status >= 400 { return nil }
	body := resp.Body
	jsURLs := make(map[string]bool)
	for _, m := range sSrcRe.FindAllStringSubmatch(body, -1) { if len(m) > 1 { r := m[1]; if strings.HasPrefix(r, "http") { jsURLs[r] = true } else { jsURLs[base+"/"+strings.TrimLeft(r, "/") ] = true } } }
	jsCont := body; cnt := 0
	for u := range jsURLs { if cnt >= 30 { break }; jr := utils.Fetch(client, u, "GET", h, 2, 500_000_000); if jr != nil && jr.Status == 200 { jsCont += "\n" + jr.Body }; cnt++ }
	eps := make(map[string]bool)
	for _, pat := range []*regexp.Regexp{apiEPRe, fetchRe, cfgRe} { for _, m := range pat.FindAllStringSubmatch(jsCont, -1) { if len(m) > 1 { eps[m[1]] = true } } }
	var allS []extractors.Secret; var allT []string; pr := 0
	for ep := range eps {
		if pr >= mx { break }
		u := ep; if !strings.HasPrefix(ep, "http") { if strings.HasPrefix(ep, "/") { u = base + ep } else { u = base + "/" + ep } }
		r := utils.Fetch(client, u, "GET", h, 2, 500_000_000); pr++
		if r == nil || r.Status == 404 || r.Status == 403 || r.Status == 502 || r.Status == 503 { continue }
		allS = append(allS, extractors.ExtractSecrets(r.Body, u)...); td := extractors.ExtractAllTargets(r.Body, u); allT = append(allT, td.IPs...); allT = append(allT, td.Domains...)
	}
	if len(allS) > 0 || len(allT) > 0 { return &core.ScanResult{URL: page, Status: resp.Status, Scanner: s.Name(), Secrets: allS, NewTargets: uniqueStrings(allT), ResponseSize: resp.Size} }
	return nil
}
