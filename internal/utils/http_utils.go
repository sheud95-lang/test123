package utils

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// ---- DNS cache ----

type dnsCacheEntry struct {
	addrs []string
	ts    time.Time
}

var (
	dnsCache    sync.Map
	dnsCacheTTL = 5 * time.Minute
)

func cachedDial(addr string, dialTimeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fasthttp.DialTimeout(addr, dialTimeout)
	}
	if net.ParseIP(host) != nil {
		return fasthttp.DialTimeout(addr, dialTimeout)
	}
	if val, ok := dnsCache.Load(host); ok {
		entry := val.(*dnsCacheEntry)
		if time.Since(entry.ts) < dnsCacheTTL && len(entry.addrs) > 0 {
			return fasthttp.DialTimeout(net.JoinHostPort(entry.addrs[0], port), dialTimeout)
		}
		dnsCache.Delete(host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return fasthttp.DialTimeout(addr, dialTimeout)
	}
	dnsCache.Store(host, &dnsCacheEntry{addrs: addrs, ts: time.Now()})
	return fasthttp.DialTimeout(net.JoinHostPort(addrs[0], port), dialTimeout)
}

func cachedDialTLS(addr string, dialTimeout time.Duration, tlsCfg *tls.Config) (net.Conn, error) {
	plainConn, err := cachedDial(addr, dialTimeout)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	cfg := tlsCfg.Clone()
	cfg.ServerName = host
	tlsConn := tls.Client(plainConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		plainConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// ---- HTTP Response ----

type HTTPResponse struct {
	URL     string
	Status  int
	Headers map[string]string
	Body    string
	Size    int
}

const maxBodySize = 5 * 1024 * 1024 // 5MB

func NewFastHTTPClient(connectTimeout, readTimeout, totalTimeout time.Duration,
	maxConnsPerHost, totalLimit int) *fasthttp.Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	return &fasthttp.Client{
		TLSConfig: tlsCfg,
		Dial: func(addr string) (net.Conn, error) {
			return cachedDial(addr, connectTimeout)
		},
		MaxConnsPerHost:     maxConnsPerHost,
		MaxIdleConnDuration: 90 * time.Second,
		ReadTimeout:         readTimeout,
		WriteTimeout:        connectTimeout,
		MaxResponseBodySize: maxBodySize,
		ReadBufferSize:      8192,
		WriteBufferSize:     4096,
	}
}

func Fetch(client *fasthttp.Client, url, method string, headers map[string]string,
	maxRetries int, retryDelay time.Duration) *HTTPResponse {
	if method == "" {
		method = "GET"
	}
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		req.SetRequestURI(url)
		req.Header.SetMethod(method)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		// DoRedirects follows up to 3 redirects automatically
		err := client.DoRedirects(req, resp, 3)
		if err != nil {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			if attempt < maxRetries {
				time.Sleep(retryDelay * time.Duration(attempt+1))
			}
			continue
		}

		// Collect headers (lowercase keys for consistent lookup)
		hdrs := make(map[string]string)
		resp.Header.VisitAll(func(key, value []byte) {
			hdrs[strings.ToLower(string(key))] = string(value)
		})

		body := string(resp.Body())
		size := len(resp.Body())
		statusCode := resp.StatusCode()

		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)

		return &HTTPResponse{
			URL:     url,
			Status:  statusCode,
			Headers: hdrs,
			Body:    body,
			Size:    size,
		}
	}
	return nil
}

func FetchRaw(ctx context.Context, client *fasthttp.Client, url string, headers map[string]string) ([]byte, int, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod("GET")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	err := client.DoRedirects(req, resp, 3)
	if err != nil {
		return nil, 0, err
	}

	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())
	return body, resp.StatusCode(), nil
}

func ContainsAny(s string, substrs []string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
