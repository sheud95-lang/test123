package scanners

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/valyala/fasthttp"

	"reaper/internal/core"
	"reaper/internal/extractors"
	"reaper/internal/utils"
)

var (
	hiddenRe    = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*['"]hidden['"][^>]*value\s*=\s*['"]([^'"]+)['"]`)
	dataAttrRe  = regexp.MustCompile(`(?i)data-(?:api[-_]?(?:key|token|url|endpoint|secret)|token|secret|key|url|config)\s*=\s*['"]([^'"]+)['"]`)
	srcMapRe    = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)
	stackRe     = regexp.MustCompile(`(?i)(?:Traceback|Exception|Error|at\s+\w+\s*\(|File\s+"[^"]+",\s*line\s+\d+)`)
	errPaths    = []string{"/404", "/500", "/error", "/debug/error", "/_error", "/undefined"}
)

type NVCAScanner struct{ WAFEvasion bool }

func (s *NVCAScanner) Name() string { return "nvca" }

func (s *NVCAScanner) Scan(client *fasthttp.Client, host string, port int, path string, isIP bool, scheme string) *core.ScanResult {
	if port == 80 { scheme = "http" }
	base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	var h map[string]string
	if s.WAFEvasion && !isIP { h = core.GenerateHeaders(host) }

	var allS []extractors.Secret; var allT []string; var pResp *utils.HTTPResponse
	for _, sp := range append([]string{path}, errPaths...) {
		p := sp; if s.WAFEvasion && !isIP { p = core.MutatePath(sp) }
		resp := utils.Fetch(client, base+p, "GET", h, 2, 150_000_000)
		if resp == nil { continue }
		if pResp == nil { pResp = resp }
		body := resp.Body
		for _, m := range hiddenRe.FindAllStringSubmatch(body, -1) { if len(m) > 1 && len(m[1]) > 6 { allS = append(allS, extractors.ExtractSecrets("HIDDEN_VALUE="+m[1], resp.URL)...) } }
		for _, m := range dataAttrRe.FindAllStringSubmatch(body, -1) { if len(m) > 1 { allS = append(allS, extractors.ExtractSecrets("DATA_ATTR="+m[1], resp.URL)...) } }
		for _, m := range srcMapRe.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 && !strings.HasPrefix(m[1], "data:") {
				mu := m[1]; if !strings.HasPrefix(mu, "http") { mu = base + "/" + strings.TrimLeft(mu, "/") }
				mr := utils.Fetch(client, mu, "GET", h, 2, 150_000_000)
				if mr != nil && mr.Status == 200 {
					// Parse sourcesContent from source map JSON for embedded source code
					var srcMap struct {
						SourcesContent []string `json:"sourcesContent"`
					}
					if json.Unmarshal([]byte(mr.Body), &srcMap) == nil && len(srcMap.SourcesContent) > 0 {
						for _, src := range srcMap.SourcesContent {
							if len(src) > 10 {
								allS = append(allS, extractors.ExtractSecrets(src, mu)...)
								td := extractors.ExtractAllTargets(src, mu)
								allT = append(allT, td.IPs...); allT = append(allT, td.Domains...)
							}
						}
					} else {
						allS = append(allS, extractors.ExtractSecrets(mr.Body, mu)...)
						td := extractors.ExtractAllTargets(mr.Body, mu)
						allT = append(allT, td.IPs...); allT = append(allT, td.Domains...)
					}
				}
			}
		}
		if stackRe.MatchString(body) { allS = append(allS, extractors.ExtractSecrets(body, resp.URL)...); td := extractors.ExtractAllTargets(body, resp.URL); allT = append(allT, td.IPs...); allT = append(allT, td.Domains...) }
	}
	if pResp != nil && (len(allS) > 0 || len(allT) > 0) {
		return &core.ScanResult{URL: base + path, Status: pResp.Status, Scanner: s.Name(), Secrets: allS, NewTargets: uniqueStrings(allT), ResponseSize: pResp.Size}
	}
	return nil
}
