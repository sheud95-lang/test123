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

var jsLinkPats = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]+src=['"]([^'"]+\.js(?:\?[^'"]*)?)['"]\s*>`),
	regexp.MustCompile(`['"]([^'"]*\.(?:js|mjs|cjs)(?:\?[^'"]*)?)['"]`),
}
var jsChunkRe = regexp.MustCompile(`['"]([^'"]*\.js(?:\?[^'"]*)?)['"]`)
var jsDefaults = []string{
	"/main.js", "/app.js", "/bundle.js", "/vendor.js",
	"/config.js", "/settings.js", "/env.js", "/runtime.js",
	"/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
	"/static/js/vendor.js", "/static/js/runtime.js",
	"/assets/js/app.js", "/assets/js/main.js",
	"/dist/bundle.js", "/dist/main.js", "/dist/app.js",
	"/js/app.js", "/js/main.js", "/js/config.js",
	"/build/static/js/main.js",
	"/webpack-runtime.js", "/manifest.json",
	"/asset-manifest.json", "/precache-manifest.js",
	"/_next/static/chunks/main.js", "/_next/static/chunks/webpack.js",
	"/static/js/runtime-main.js",
	"/chunk-vendors.js", "/chunk-common.js",
}

type JSScanner struct{ WAFEvasion bool; MaxJSFiles int }

func (s *JSScanner) Name() string { return "js" }

func (s *JSScanner) Scan(client *fasthttp.Client, host string, port int, path string, isIP bool, scheme string) *core.ScanResult {
	if port == 80 { scheme = "http" }
	mx := s.MaxJSFiles; if mx <= 0 { mx = 50 }
	base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	page := base + path
	var h map[string]string
	if s.WAFEvasion && !isIP { h = core.GenerateHeaders(host) }
	resp := utils.Fetch(client, page, "GET", h, 2, 150_000_000)
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

	// Parse asset-manifest.json / manifest.json for extra JS chunk URLs
	for _, mp := range []string{"/asset-manifest.json", "/manifest.json", "/build/asset-manifest.json"} {
		mr := utils.Fetch(client, base+mp, "GET", h, 1, 150_000_000)
		if mr != nil && mr.Status == 200 && strings.Contains(mr.Body, ".js") {
			for _, m := range jsChunkRe.FindAllStringSubmatch(mr.Body, -1) {
				if len(m) > 1 {
					ref := m[1]
					if strings.HasPrefix(ref, "http") { jsURLs[ref] = true } else if strings.HasPrefix(ref, "/") { jsURLs[base+ref] = true } else { jsURLs[base+"/"+ref] = true }
				}
			}
		}
	}

	var allS []extractors.Secret; var allT []string; sc := 0
	for u := range jsURLs {
		if sc >= mx { break }
		jr := utils.Fetch(client, u, "GET", h, 2, 150_000_000)
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
