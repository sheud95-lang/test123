package scanners

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/valyala/fasthttp"

	"reaper/internal/core"
	"reaper/internal/extractors"
	"reaper/internal/utils"
)

var (
	gitPaths2 = []string{
		"/.git/config", "/.git/HEAD", "/.git/index",
		"/.git/logs/HEAD", "/.git/FETCH_HEAD", "/.git/ORIG_HEAD",
		"/.git/refs/heads/master", "/.git/refs/heads/main", "/.git/refs/heads/develop",
		"/.git/description", "/.git/packed-refs",
	}
	gitMarkers  = []string{"[core]", "[remote", "[branch", "repositoryformatversion"}
	sha1Re      = regexp.MustCompile(`\b[0-9a-f]{40}\b`)
)

type GitScanner struct{ WAFEvasion bool; MaxObjects int }

func (s *GitScanner) Name() string { return "git" }

func (s *GitScanner) Scan(client *fasthttp.Client, host string, port int, path string, isIP bool, scheme string) *core.ScanResult {
	if port == 80 { scheme = "http" }
	mx := s.MaxObjects; if mx <= 0 { mx = 50 }
	base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	var h map[string]string
	if s.WAFEvasion && !isIP { h = core.GenerateHeaders(host) }
	var allS []extractors.Secret; var allT []string; exposed := false
	for _, gp := range gitPaths2 {
		u := base + gp; r := utils.Fetch(client, u, "GET", h, 2, 150_000_000)
		if r == nil || r.Status != 200 { continue }
		body := r.Body
		if strings.HasSuffix(gp, "/config") { for _, mk := range gitMarkers { if strings.Contains(body, mk) { exposed = true; allS = append(allS, extractors.ExtractSecrets(body, u)...); td := extractors.ExtractAllTargets(body, u); allT = append(allT, td.IPs...); allT = append(allT, td.Domains...); break } } } else if strings.HasSuffix(gp, "/HEAD") { t := strings.TrimSpace(body); if strings.HasPrefix(t, "ref:") || sha1Re.MatchString(t) { exposed = true } } else { if sha1Re.MatchString(body) { exposed = true }; allS = append(allS, extractors.ExtractSecrets(body, u)...) }
	}
	if !exposed { return nil }
	shas := make(map[string]bool)
	for _, sp := range []string{"/.git/logs/HEAD", "/.git/packed-refs", "/.git/refs/heads/master", "/.git/refs/heads/main", "/.git/FETCH_HEAD", "/.git/ORIG_HEAD"} {
		r := utils.Fetch(client, base+sp, "GET", h, 2, 150_000_000)
		if r != nil && r.Status == 200 { for _, sha := range sha1Re.FindAllString(r.Body, -1) { shas[sha] = true } }
	}
	fetched := 0
	pending := make(map[string]bool)
	for sha := range shas {
		pending[sha] = true
	}
	for len(pending) > 0 && fetched < mx {
		batch := pending
		pending = make(map[string]bool)
		for sha := range batch {
			if fetched >= mx { break }
			u := fmt.Sprintf("%s/.git/objects/%s/%s", base, sha[:2], sha[2:])
			data, st, err := utils.FetchRaw(context.TODO(), client, u, h)
			if err != nil || st != 200 { continue }; fetched++
			rd, err := zlib.NewReader(bytes.NewReader(data)); if err != nil { continue }
			dec, err := io.ReadAll(rd); rd.Close(); if err != nil { continue }
			text := string(dec)
			allS = append(allS, extractors.ExtractSecrets(text, u)...); td := extractors.ExtractAllTargets(text, u); allT = append(allT, td.IPs...); allT = append(allT, td.Domains...)
			for _, ns := range sha1Re.FindAllString(text, -1) {
				if !shas[ns] {
					shas[ns] = true
					pending[ns] = true
				}
			}
		}
	}
	if len(allS) > 0 || len(allT) > 0 { return &core.ScanResult{URL: base + "/.git/", Status: 200, Scanner: s.Name(), Secrets: allS, NewTargets: uniqueStrings(allT)} }
	return nil
}
