package core

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"sync"
)

// WAF bypass levels
const (
	WAFLevel1 = 1 // Basic: random headers + simple path mutation
	WAFLevel2 = 2 // Double encoding, case mutation, param pollution, null bytes
	WAFLevel3 = 3 // Header stacking, junk params, path normalization tricks
	WAFLevel4 = 4 // CDN-specific (Cloudflare, Akamai, AWS WAF)
	WAFLevel5 = 5 // Adaptive: escalates based on response
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"curl/8.7.1",
	"python-requests/2.32.3",
	"Go-http-client/2.0",
}

var acceptH = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"*/*",
	"application/json, text/plain, */*",
}
var acceptL = []string{
	"en-US,en;q=0.9", "en-GB,en;q=0.8", "de-DE,de;q=0.9,en;q=0.8",
	"ru-RU,ru;q=0.9,en;q=0.5",
}
var refs = []string{
	"https://www.google.com/", "https://www.bing.com/", "",
}

const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

func rStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func rIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(223)+1, rand.Intn(256), rand.Intn(256), rand.Intn(254)+1)
}

// GenerateHeaders generates Level 1 WAF bypass headers (backward compatible).
func GenerateHeaders(customHost string) map[string]string {
	return GenerateHeadersL(WAFLevel1, customHost)
}

// GenerateHeadersL generates WAF bypass headers at the specified level.
func GenerateHeadersL(level int, customHost string) map[string]string {
	h := map[string]string{
		"User-Agent":      userAgents[rand.Intn(len(userAgents))],
		"Accept":          acceptH[rand.Intn(len(acceptH))],
		"Accept-Language": acceptL[rand.Intn(len(acceptL))],
		"Accept-Encoding": "gzip, deflate, br",
		"Connection":      "keep-alive",
	}
	if ref := refs[rand.Intn(len(refs))]; ref != "" {
		h["Referer"] = ref
	}
	if customHost != "" {
		h["Host"] = customHost
	}

	// Level 1: basic random headers
	tricks := []struct{ k, v string }{
		{"X-Forwarded-For", rIP()},
		{"X-Real-IP", rIP()},
		{"X-Originating-IP", "127.0.0.1"},
		{"X-Custom-IP-Authorization", "127.0.0.1"},
		{"X-Original-URL", "/" + rStr(4)},
	}
	n := rand.Intn(3) + 1
	perm := rand.Perm(len(tricks))
	for i := 0; i < n && i < len(perm); i++ {
		t := tricks[perm[i]]
		h[t.k] = t.v
	}

	if level >= WAFLevel3 {
		// Header stacking: multiple forwarded IPs
		h["X-Forwarded-For"] = fmt.Sprintf("%s, %s, %s", rIP(), rIP(), "127.0.0.1")
		h["Forwarded"] = fmt.Sprintf("for=%s;proto=https;by=%s", rIP(), rIP())
		h["X-Forwarded-Host"] = customHost
		if customHost == "" {
			h["X-Forwarded-Host"] = rStr(8) + ".com"
		}
		h["X-Forwarded-Proto"] = "https"
		// Add more IP-related headers
		extra := []struct{ k, v string }{
			{"X-Client-IP", rIP()},
			{"CF-Connecting-IP", rIP()},
			{"True-Client-IP", rIP()},
			{"X-Cluster-Client-IP", rIP()},
			{"X-ProxyUser-Ip", rIP()},
		}
		for _, e := range extra {
			if rand.Float64() < 0.4 {
				h[e.k] = e.v
			}
		}
	}

	if level >= WAFLevel4 {
		// CDN-specific headers
		cdnHeaders := []struct{ k, v string }{
			{"CF-Connecting-IP", "127.0.0.1"},
			{"True-Client-IP", "127.0.0.1"},
			{"X-Forwarded-For", "127.0.0.1"},
			{"Fastly-Client-IP", rIP()},
			{"Akamai-Origin-Hop", "1"},
			{"X-Azure-ClientIP", rIP()},
			{"X-CDN", "Imperva"},
		}
		for _, ch := range cdnHeaders {
			if rand.Float64() < 0.3 {
				h[ch.k] = ch.v
			}
		}
		// Content-Type confusion
		if rand.Float64() < 0.2 {
			ct := []string{
				"application/x-www-form-urlencoded",
				"multipart/form-data",
				"text/xml",
			}
			h["Content-Type"] = ct[rand.Intn(len(ct))]
		}
	}

	return h
}

// MutatePath applies Level 1 path mutation (backward compatible).
func MutatePath(path string) string {
	return MutatePathL(WAFLevel1, path)
}

// MutatePathL applies path mutation at the specified WAF level.
func MutatePathL(level int, path string) string {
	if level <= 1 {
		return mutatePathL1(path)
	}
	if level == 2 {
		return mutatePathL2(path)
	}
	if level == 3 {
		return mutatePathL3(path)
	}
	// Level 4-5: combine L3 mutations with extra tricks
	return mutatePathL4(path)
}

// Level 1: basic mutations (original behavior)
func mutatePathL1(path string) string {
	switch rand.Intn(7) {
	case 0:
		for i, r := range path {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				if rand.Float64() < 0.15 {
					return path[:i] + url.QueryEscape(string(r)) + path[i+1:]
				}
			}
		}
	case 6:
		for i, r := range path {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				if rand.Float64() < 0.15 {
					e := url.QueryEscape(string(r))
					return path[:i] + url.QueryEscape(e) + path[i+1:]
				}
			}
		}
	case 1:
		runes := []rune(path)
		for i := range runes {
			if runes[i] >= 'a' && runes[i] <= 'z' && rand.Float64() < 0.3 {
				runes[i] -= 32
			} else if runes[i] >= 'A' && runes[i] <= 'Z' && rand.Float64() < 0.3 {
				runes[i] += 32
			}
		}
		return string(runes)
	case 2:
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return fmt.Sprintf("%s%s%s=%s", path, sep, rStr(3), rStr(5))
	case 3:
		ss := []string{"/", "//", "/.", ";.css", ";.js", "%23"}
		return path + ss[rand.Intn(len(ss))]
	case 4:
		if idx := strings.Index(path[1:], "/"); idx > 0 {
			idx++
			return path[:idx] + "/" + rStr(4) + "/.." + path[idx:]
		}
	}
	return path
}

// Level 2: double encoding, HPP, null bytes, unicode normalization
func mutatePathL2(path string) string {
	switch rand.Intn(8) {
	case 0, 1:
		return mutatePathL1(path) // include L1 techniques
	case 2:
		// Double URL encoding of entire path segments
		parts := strings.Split(path, "/")
		idx := rand.Intn(len(parts))
		if len(parts[idx]) > 0 {
			var encoded strings.Builder
			for _, c := range parts[idx] {
				e := url.QueryEscape(string(c))
				encoded.WriteString(url.QueryEscape(e))
			}
			parts[idx] = encoded.String()
		}
		return strings.Join(parts, "/")
	case 3:
		// Null byte before extension
		if dotIdx := strings.LastIndex(path, "."); dotIdx > 0 {
			return path[:dotIdx] + "%00" + path[dotIdx:]
		}
		return path + "%00.html"
	case 4:
		// HPP: duplicate parameters
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return fmt.Sprintf("%s%s%s=%s&%s=%s", path, sep, rStr(3), rStr(5), rStr(3), rStr(5))
	case 5:
		// Unicode normalization bypass: %c0%af for /
		return strings.Replace(path, "/", "%c0%af", 1+rand.Intn(2))
	case 6:
		// Mixed case on directory names (more aggressive than L1)
		runes := []rune(path)
		for i := range runes {
			if runes[i] >= 'a' && runes[i] <= 'z' && rand.Float64() < 0.5 {
				runes[i] -= 32
			}
		}
		return string(runes)
	case 7:
		// Backslash substitution (IIS)
		return strings.ReplaceAll(path, "/", "\\")
	}
	return path
}

// Level 3: path normalization, junk params, advanced tricks
func mutatePathL3(path string) string {
	switch rand.Intn(10) {
	case 0, 1, 2:
		return mutatePathL2(path) // include L2 techniques
	case 3:
		// Path normalization: /./ insertion
		if idx := strings.Index(path[1:], "/"); idx > 0 {
			idx++
			return path[:idx] + "/./" + path[idx+1:]
		}
	case 4:
		// Double slash
		if idx := strings.Index(path[1:], "/"); idx > 0 {
			idx++
			return path[:idx] + "/" + path[idx:]
		}
	case 5:
		// Semicolon path parameter
		if idx := strings.Index(path[1:], "/"); idx > 0 {
			idx++
			return path[:idx] + ";/" + path[idx+1:]
		}
	case 6:
		// Junk query parameters
		junk := []string{
			fmt.Sprintf("_=%d", rand.Int63()),
			fmt.Sprintf("cb=%s", rStr(8)),
			fmt.Sprintf("nocache=%d", rand.Intn(99999)),
			fmt.Sprintf("utm_source=%s&utm_medium=%s", rStr(5), rStr(5)),
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return path + sep + junk[rand.Intn(len(junk))]
	case 7:
		// Tab or newline injection (%09, %0a)
		if idx := strings.LastIndex(path, "/"); idx >= 0 {
			return path[:idx+1] + "%09" + path[idx+1:]
		}
	case 8:
		// URL fragment to confuse parsers
		return path + "%23" + rStr(4)
	case 9:
		// Triple dot traversal
		if idx := strings.Index(path[1:], "/"); idx > 0 {
			idx++
			return path[:idx] + "/.../" + path[idx+1:]
		}
	}
	return path
}

// Level 4: CDN-specific + all lower level tricks
func mutatePathL4(path string) string {
	switch rand.Intn(8) {
	case 0, 1, 2, 3:
		return mutatePathL3(path)
	case 4:
		// Cloudflare: /cdn-cgi/ prefix tricks
		return "/cdn-cgi/l/email-protection" + path
	case 5:
		// Long URI padding to overflow WAF buffers
		padding := strings.Repeat("A", 2000+rand.Intn(2000))
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return path + sep + "x=" + padding
	case 6:
		// Chunked path encoding: mix encoded and unencoded
		var result strings.Builder
		for i, r := range path {
			if i > 0 && r != '/' && rand.Float64() < 0.3 {
				result.WriteString(fmt.Sprintf("%%%02X", r))
			} else {
				result.WriteRune(r)
			}
		}
		return result.String()
	case 7:
		// HTTP method override via query
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		methods := []string{"_method=GET", "X-HTTP-Method-Override=GET", "X-Method-Override=GET"}
		return path + sep + methods[rand.Intn(len(methods))]
	}
	return path
}

// ---- Adaptive WAF Tracker (Level 5) ----

type targetWAFState struct {
	level      int
	blockCount int
	cdnType    string // "cloudflare", "akamai", "aws", ""
}

type WAFTracker struct {
	mu     sync.Mutex
	states map[string]*targetWAFState
}

func NewWAFTracker() *WAFTracker {
	return &WAFTracker{states: make(map[string]*targetWAFState)}
}

func (wt *WAFTracker) GetLevel(host string, baseLevel int) int {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	if s, ok := wt.states[host]; ok {
		if s.level > baseLevel {
			return s.level
		}
	}
	return baseLevel
}

func (wt *WAFTracker) RecordBlock(host string, statusCode int, body string) {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	s, ok := wt.states[host]
	if !ok {
		s = &targetWAFState{level: WAFLevel1}
		wt.states[host] = s
	}

	if statusCode == 403 || statusCode == 406 || statusCode == 429 {
		s.blockCount++
	}

	// Detect CDN type from response body
	if s.cdnType == "" {
		bodyLower := strings.ToLower(body)
		switch {
		case strings.Contains(bodyLower, "cloudflare") || strings.Contains(bodyLower, "cf-ray"):
			s.cdnType = "cloudflare"
		case strings.Contains(bodyLower, "akamai") || strings.Contains(bodyLower, "akamaighost"):
			s.cdnType = "akamai"
		case strings.Contains(bodyLower, "awselb") || strings.Contains(bodyLower, "aws-waf"):
			s.cdnType = "aws"
		case strings.Contains(bodyLower, "incapsula") || strings.Contains(bodyLower, "imperva"):
			s.cdnType = "imperva"
		}
	}

	// Escalate level based on block count
	switch {
	case s.blockCount >= 8:
		s.level = WAFLevel5
	case s.blockCount >= 5:
		s.level = WAFLevel4
	case s.blockCount >= 3:
		s.level = WAFLevel3
	case s.blockCount >= 1:
		s.level = WAFLevel2
	}

	// If CDN detected, jump to L4 minimum
	if s.cdnType != "" && s.level < WAFLevel4 {
		s.level = WAFLevel4
	}
}
