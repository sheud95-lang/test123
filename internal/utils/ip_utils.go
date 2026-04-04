package utils

import (
	"net"
	"regexp"
	"strings"
)

var (
	privateNets []*net.IPNet
	IPv4Pattern = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
)

func init() {
	for _, c := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
		"::1/128", "fc00::/7", "fe80::/10",
	} {
		_, ipnet, err := net.ParseCIDR(c)
		if err == nil {
			privateNets = append(privateNets, ipnet)
		}
	}
}

func IsValidIP(addr string) bool {
	return net.ParseIP(strings.Trim(addr, "[]")) != nil
}

func IsPrivateIP(addr string) bool {
	ip := net.ParseIP(strings.Trim(addr, "[]"))
	if ip == nil {
		return false
	}
	for _, pn := range privateNets {
		if pn.Contains(ip) {
			return true
		}
	}
	return false
}

func ExtractIPsFromText(text string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, m := range IPv4Pattern.FindAllString(text, -1) {
		if IsValidIP(m) && !seen[m] {
			seen[m] = true
			result = append(result, m)
		}
	}
	return result
}

func FilterIPs(ips []string, excludePrivate bool, blacklist map[string]bool) []string {
	if blacklist == nil {
		blacklist = make(map[string]bool)
	}
	var result []string
	for _, ip := range ips {
		if blacklist[ip] || (excludePrivate && IsPrivateIP(ip)) {
			continue
		}
		if IsValidIP(ip) {
			result = append(result, ip)
		}
	}
	return result
}
