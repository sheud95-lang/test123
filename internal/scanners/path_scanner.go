package scanners

import (
	"fmt"
	"net/http"

	"reaper/internal/core"
	"reaper/internal/extractors"
	"reaper/internal/utils"
)

type PathScanner struct{ WAFEvasion bool }

func (s *PathScanner) Name() string { return "path" }

func (s *PathScanner) Scan(client *http.Client, host string, port int, path string, isIP bool, scheme string) *core.ScanResult {
	if port == 80 { scheme = "http" }
	p := path
	if s.WAFEvasion { p = core.MutatePath(path) }
	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, p)
	var h map[string]string
	if s.WAFEvasion {
		ch := ""
		if !isIP { ch = host }
		h = core.GenerateHeaders(ch)
	}
	resp := utils.Fetch(client, url, "GET", h, 2, 500_000_000)
	if resp == nil || resp.Status == 404 || resp.Status == 403 || resp.Status == 503 || resp.Status == 502 {
		return nil
	}
	secrets := extractors.ExtractSecrets(resp.Body, url)
	td := extractors.ExtractAllTargets(resp.Body, url)
	nt := append(td.IPs, td.Domains...)
	if len(secrets) > 0 || len(nt) > 0 {
		return &core.ScanResult{URL: resp.URL, Status: resp.Status, Scanner: s.Name(), Secrets: secrets, NewTargets: nt, ResponseSize: resp.Size}
	}
	return nil
}
