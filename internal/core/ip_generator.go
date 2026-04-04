package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"reaper/internal/config"
)

var reservedNets []*net.IPNet

func init() {
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	} {
		_, ipnet, _ := net.ParseCIDR(c)
		if ipnet != nil {
			reservedNets = append(reservedNets, ipnet)
		}
	}
}

var hostingRanges = []string{
	"3.0.0.0/15", "13.32.0.0/15", "18.64.0.0/14",
	"34.192.0.0/12", "52.0.0.0/11", "54.64.0.0/11",
	"34.64.0.0/11", "35.184.0.0/13",
	"13.64.0.0/11", "20.0.0.0/11", "40.64.0.0/10",
	"64.225.0.0/16", "67.205.128.0/17", "68.183.0.0/16",
	"134.122.0.0/16", "137.184.0.0/16", "138.68.0.0/16",
	"139.59.0.0/16", "142.93.0.0/16", "143.110.0.0/16",
	"143.198.0.0/16", "146.190.0.0/16", "147.182.0.0/16",
	"157.230.0.0/16", "159.65.0.0/16", "159.89.0.0/16",
	"161.35.0.0/16", "164.90.0.0/16", "164.92.0.0/16",
	"165.22.0.0/16", "165.227.0.0/16", "167.71.0.0/16",
	"167.172.0.0/16", "174.138.0.0/16", "178.128.0.0/16",
	"188.166.0.0/16", "206.189.0.0/16", "209.97.0.0/16",
	"5.9.0.0/16", "46.4.0.0/16", "49.12.0.0/16", "49.13.0.0/16",
	"65.108.0.0/16", "65.109.0.0/16", "78.46.0.0/15",
	"88.198.0.0/16", "88.99.0.0/16", "95.216.0.0/16",
	"116.202.0.0/16", "116.203.0.0/16", "135.181.0.0/16",
	"136.243.0.0/16", "138.201.0.0/16", "142.132.0.0/16",
	"144.76.0.0/16", "148.251.0.0/16", "157.90.0.0/16",
	"159.69.0.0/16", "162.55.0.0/16", "167.235.0.0/16",
	"168.119.0.0/16", "176.9.0.0/16", "178.63.0.0/16",
	"188.40.0.0/16", "195.201.0.0/16",
	"51.38.0.0/16", "51.68.0.0/16", "51.75.0.0/16",
	"51.77.0.0/16", "51.79.0.0/16", "51.89.0.0/16",
	"54.36.0.0/16", "54.37.0.0/16", "54.38.0.0/16",
	"135.125.0.0/16", "137.74.0.0/16", "141.94.0.0/16",
	"145.239.0.0/16", "147.135.0.0/16", "149.202.0.0/16",
	"45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "45.77.0.0/16",
	"66.42.0.0/16", "78.141.0.0/16", "95.179.0.0/16",
	"108.61.0.0/16", "136.244.0.0/16", "140.82.0.0/16",
	"144.202.0.0/16", "149.28.0.0/16", "155.138.0.0/16",
	"45.33.0.0/17", "45.79.0.0/16", "139.144.0.0/16",
	"143.42.0.0/16", "172.232.0.0/14",
}

func isReserved(ip net.IP) bool {
	for _, rn := range reservedNets {
		if rn.Contains(ip) {
			return true
		}
	}
	return false
}

func GenerateRandomIPs(count int) []string {
	ips := make([]string, 0, count)
	for attempts := 0; len(ips) < count && attempts < count*3; attempts++ {
		v := rand.Uint32()&0xDFFFFFFF + 1
		ip := net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
		if !isReserved(ip) {
			ips = append(ips, ip.String())
		}
	}
	return ips
}

func GenerateFromRanges(count int) []string {
	var networks []*net.IPNet
	for _, r := range hostingRanges {
		_, ipnet, err := net.ParseCIDR(r)
		if err == nil {
			networks = append(networks, ipnet)
		}
	}
	seen := make(map[string]bool)
	var ips []string
	for attempts := 0; len(ips) < count && attempts < count*5; attempts++ {
		n := networks[rand.Intn(len(networks))]
		ones, bits := n.Mask.Size()
		numAddrs := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
		if numAddrs.Int64() <= 2 {
			continue
		}
		offset := rand.Int63n(numAddrs.Int64()-2) + 1
		ipInt := new(big.Int).SetBytes(n.IP.To4())
		ipInt.Add(ipInt, big.NewInt(offset))
		b := ipInt.Bytes()
		for len(b) < 4 {
			b = append([]byte{0}, b...)
		}
		ip := net.IP(b).String()
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

type HostPort struct {
	Host string
	Port int
}

func PortPrecheck(ips []string, ports []int, timeout time.Duration, conc int) []HostPort {
	var alive []HostPort
	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var checked int64
	total := int64(len(ips) * len(ports))

	for _, ip := range ips {
		for _, port := range ports {
			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, p), timeout)
				if err == nil {
					conn.Close()
					mu.Lock()
					alive = append(alive, HostPort{Host: h, Port: p})
					mu.Unlock()
				}
				if c := atomic.AddInt64(&checked, 1); c%10000 == 0 {
					mu.Lock()
					log.Printf("Precheck: %d/%d (%d alive)", c, total, len(alive))
					mu.Unlock()
				}
			}(ip, port)
		}
	}
	wg.Wait()
	log.Printf("Precheck done: %d alive / %d", len(alive), total)
	return alive
}

func FetchFromShodan(apiKey string, max int) []string {
	if apiKey == "" {
		return nil
	}
	var ips []string
	client := &http.Client{Timeout: 30 * time.Second}
	for _, q := range []string{"port:80 http", "port:443 ssl", "port:8080 http"} {
		if len(ips) >= max {
			break
		}
		for page := 1; page <= 5 && len(ips) < max; page++ {
			u := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&page=%d", apiKey, url.QueryEscape(q), page)
			resp, err := client.Get(u)
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				break
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var data struct {
				Matches []struct {
					IP string `json:"ip_str"`
				} `json:"matches"`
			}
			if json.Unmarshal(body, &data) != nil || len(data.Matches) == 0 {
				break
			}
			for _, m := range data.Matches {
				if m.IP != "" {
					ips = append(ips, m.IP)
				}
			}
		}
	}
	if len(ips) > max {
		ips = ips[:max]
	}
	return ips
}

func FetchFromCensys(apiID, apiSecret string, max int) []string {
	if apiID == "" || apiSecret == "" {
		return nil
	}
	var ips []string
	auth := base64.StdEncoding.EncodeToString([]byte(apiID + ":" + apiSecret))
	client := &http.Client{Timeout: 30 * time.Second}
	for _, q := range []string{"services.port=80", "services.port=443"} {
		if len(ips) >= max {
			break
		}
		cursor := ""
		for i := 0; i < 50 && len(ips) < max; i++ {
			u := fmt.Sprintf("https://search.censys.io/api/v2/hosts/search?q=%s&per_page=100", url.QueryEscape(q))
			if cursor != "" {
				u += "&cursor=" + cursor
			}
			req, _ := http.NewRequest("GET", u, nil)
			req.Header.Set("Authorization", "Basic "+auth)
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				break
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var data struct {
				Result struct {
					Hits  []struct{ IP string `json:"ip"` } `json:"hits"`
					Links struct{ Next string `json:"next"` } `json:"links"`
				} `json:"result"`
			}
			if json.Unmarshal(body, &data) != nil || len(data.Result.Hits) == 0 {
				break
			}
			for _, h := range data.Result.Hits {
				ips = append(ips, h.IP)
			}
			cursor = data.Result.Links.Next
			if cursor == "" {
				break
			}
		}
	}
	if len(ips) > max {
		ips = ips[:max]
	}
	return ips
}

type IPGenerator struct {
	Config    *config.ScanConfig
	Generated []string
	Alive     []HostPort
}

func NewIPGenerator(cfg *config.ScanConfig) *IPGenerator {
	return &IPGenerator{Config: cfg}
}

func (g *IPGenerator) Generate(ctx context.Context) ([]HostPort, error) {
	mode := g.Config.TargetMode
	tc := g.Config.MaxTargets
	allIPs := make(map[string]bool)

	if mode == "random" || mode == "all" {
		c := tc
		if mode == "all" {
			c = tc / 3
		}
		for _, ip := range GenerateRandomIPs(c) {
			allIPs[ip] = true
		}
	}
	if mode == "ranges" || mode == "all" {
		c := tc
		if mode == "all" {
			c = tc / 3
		}
		for _, ip := range GenerateFromRanges(c) {
			allIPs[ip] = true
		}
	}
	if mode == "api" || mode == "all" {
		third := tc / 3
		for _, ip := range FetchFromShodan(g.Config.ShodanAPIKey, third) {
			allIPs[ip] = true
		}
		for _, ip := range FetchFromCensys(g.Config.CensysAPIID, g.Config.CensysAPISecret, third) {
			allIPs[ip] = true
		}
	}

	g.Generated = make([]string, 0, len(allIPs))
	for ip := range allIPs {
		if len(g.Generated) >= tc {
			break
		}
		g.Generated = append(g.Generated, ip)
	}
	log.Printf("Total unique IPs: %d", len(g.Generated))

	if g.Config.PrecheckPorts {
		g.Alive = PortPrecheck(g.Generated, g.Config.Ports, g.Config.PrecheckTimeout, g.Config.PrecheckConcurrency)
	} else {
		for _, ip := range g.Generated {
			for _, port := range g.Config.Ports {
				g.Alive = append(g.Alive, HostPort{Host: ip, Port: port})
			}
		}
	}
	log.Printf("Alive targets: %d", len(g.Alive))
	return g.Alive, nil
}
