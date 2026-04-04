package scanners

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/valyala/fasthttp"

	"reaper/internal/core"
	"reaper/internal/extractors"
	"reaper/internal/utils"
)

var (
	hdrSecrets  = []string{"x-api-key", "authorization", "x-auth-token", "x-access-token", "set-cookie", "x-powered-by", "server", "x-debug", "x-debug-token", "www-authenticate"}
	commentRe   = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	inlineJSRe  = regexp.MustCompile(`(?si)<script[^>]*>(.*?)</script>`)
	metaRe      = regexp.MustCompile(`(?i)<meta[^>]+(?:content|value)\s*=\s*['"]([^'"]+)['"][^>]*>`)
)

type R2SScanner struct{ WAFEvasion bool }

func (s *R2SScanner) Name() string { return "r2s" }

func (s *R2SScanner) Scan(client *fasthttp.Client, host string, port int, path string, isIP bool, scheme string) *core.ScanResult {
	if port == 80 { scheme = "http" }
	p := path; if s.WAFEvasion { p = core.MutatePath(path) }
	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, p)
	var h map[string]string
	if s.WAFEvasion { ch := ""; if !isIP { ch = host }; h = core.GenerateHeaders(ch) }
	resp := utils.Fetch(client, url, "GET", h, 2, 500_000_000)
	if resp == nil { return nil }

	var allS []extractors.Secret; var allT []string
	var hp []string
	for _, hn := range hdrSecrets { if v, ok := resp.Headers[hn]; ok && v != "" { hp = append(hp, hn+"="+v) } }
	if len(hp) > 0 { allS = append(allS, extractors.ExtractSecrets(strings.Join(hp, "\n"), url)...) }
	body := resp.Body
	for _, m := range commentRe.FindAllStringSubmatch(body, -1) { if len(m) > 1 { allS = append(allS, extractors.ExtractSecrets(m[1], url)...); td := extractors.ExtractAllTargets(m[1], url); allT = append(allT, td.IPs...); allT = append(allT, td.Domains...) } }
	for _, m := range inlineJSRe.FindAllStringSubmatch(body, -1) { if len(m) > 1 && len(m[1]) > 5 { allS = append(allS, extractors.ExtractSecrets(m[1], url)...) } }
	for _, m := range metaRe.FindAllStringSubmatch(body, -1) { if len(m) > 1 { allS = append(allS, extractors.ExtractSecrets(m[1], url)...) } }
	allS = append(allS, extractors.ExtractSecrets(body, url)...)
	td := extractors.ExtractAllTargets(body, url); allT = append(allT, td.IPs...); allT = append(allT, td.Domains...)
	if len(allS) > 0 || len(allT) > 0 {
		return &core.ScanResult{URL: resp.URL, Status: resp.Status, Scanner: s.Name(), Secrets: allS, NewTargets: uniqueStrings(allT), ResponseSize: resp.Size}
	}
	return nil
}
