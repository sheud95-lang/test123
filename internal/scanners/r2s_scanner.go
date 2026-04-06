package scanners

import (
	"fmt"
	"strings"

	"github.com/valyala/fasthttp"

	"reaper/internal/core"
	"reaper/internal/extractors"
	"reaper/internal/utils"
)

var hdrSecrets = []string{"x-api-key", "authorization", "x-auth-token", "x-access-token", "set-cookie", "x-powered-by", "server", "x-debug", "x-debug-token", "www-authenticate"}

type R2SScanner struct{ WAFEvasion bool }

func (s *R2SScanner) Name() string { return "r2s" }

func (s *R2SScanner) Scan(client *fasthttp.Client, host string, port int, path string, isIP bool, scheme string) *core.ScanResult {
	if port == 80 { scheme = "http" }
	p := path; if s.WAFEvasion && !isIP { p = core.MutatePath(path) }
	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, p)
	var h map[string]string
	if s.WAFEvasion && !isIP { h = core.GenerateHeaders(host) }
	resp := utils.Fetch(client, url, "GET", h, 2, 150_000_000)
	if resp == nil { return nil }

	var allS []extractors.Secret; var allT []string
	var hp []string
	for _, hn := range hdrSecrets { if v, ok := resp.Headers[hn]; ok && v != "" { hp = append(hp, hn+"="+v) } }
	if len(hp) > 0 { allS = append(allS, extractors.ExtractSecrets(strings.Join(hp, "\n"), url)...) }
	body := resp.Body
	// Extract secrets from full body only — body already contains comments, inline JS, meta tags
	// Extracting from subsets separately caused duplicate work and duplicate results
	allS = append(allS, extractors.ExtractSecrets(body, url)...)
	td := extractors.ExtractAllTargets(body, url); allT = append(allT, td.IPs...); allT = append(allT, td.Domains...)
	if len(allS) > 0 || len(allT) > 0 {
		return &core.ScanResult{URL: resp.URL, Status: resp.Status, Scanner: s.Name(), Secrets: allS, NewTargets: uniqueStrings(allT), ResponseSize: resp.Size}
	}
	return nil
}
