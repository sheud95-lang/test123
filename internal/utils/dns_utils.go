package utils

import (
	"context"
	"net"
	"sync"
	"time"
)

func ResolveDomain(domain string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := (&net.Resolver{}).LookupHost(ctx, domain)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var u []string
	for _, a := range addrs {
		if !seen[a] {
			seen[a] = true
			u = append(u, a)
		}
	}
	return u
}

func EnumerateSubdomains(domain string, prefixes []string) []struct {
	Subdomain string
	IPs       []string
} {
	if prefixes == nil {
		prefixes = []string{
			"www", "mail", "ftp", "admin", "dev", "staging", "api", "app",
			"test", "beta", "portal", "vpn", "cdn", "static", "assets",
			"ns1", "ns2", "mx", "smtp", "pop", "imap", "webmail",
			"git", "gitlab", "jenkins", "ci", "cd", "docker", "k8s",
			"monitor", "grafana", "kibana", "elastic", "db", "mysql",
			"postgres", "redis", "mongo", "minio", "s3", "backup",
			"internal", "intranet", "uat", "qa", "sandbox", "demo",
		}
	}
	type r struct {
		S string
		I []string
	}
	var mu sync.Mutex
	var found []r
	sem := make(chan struct{}, 100)
	var wg sync.WaitGroup
	for _, p := range prefixes {
		wg.Add(1)
		go func(px string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			sub := px + "." + domain
			ips := ResolveDomain(sub)
			if len(ips) > 0 {
				mu.Lock()
				found = append(found, r{S: sub, I: ips})
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	out := make([]struct {
		Subdomain string
		IPs       []string
	}, len(found))
	for i, f := range found {
		out[i].Subdomain = f.S
		out[i].IPs = f.I
	}
	return out
}
