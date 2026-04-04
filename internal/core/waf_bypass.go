package core

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
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

func GenerateHeaders(customHost string) map[string]string {
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
	return h
}

func MutatePath(path string) string {
	switch rand.Intn(6) {
	case 0:
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
