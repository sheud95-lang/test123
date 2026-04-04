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
	// Skip cache for IPs
	if net.ParseIP(host) != nil {
		return fasthttp.DialTimeout(addr, dialTimeout)
	}
	// Check cache
	if val, ok := dnsCache.Load(host); ok {
		entry := val.(*dnsCacheEntry)
		if time.Since(entry.ts) < dnsCacheTTL && len(entry.addrs) > 0 {
			return fasthttp.DialTimeout(net.JoinHostPort(entry.addrs[0], port), dialTimeout)
		}
		dnsCache.Delete(host)
	}
	// Resolve and cache
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return fasthttp.DialTimeout(addr, dialTimeout)
	}
	dnsCache.Store(host, &dnsCacheEntry{addrs: addrs, ts: time.Now()})
	return fasthttp.DialTimeout(net.JoinHostPort(addrs[0], port), dialTimeout)
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
	return &fasthttp.Client{
		// InsecureSkipVerify: scanning tool connecting to arbitrary hosts with self-signed/expired certs.
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: func(addr string) (net.Conn, error) {
			return cachedDial(addr, connectTimeout)
		},
		MaxConnsPerHost:               maxConnsPerHost,
		MaxIdleConnDuration:           90 * time.Second,
		ReadTimeout:                   readTimeout,
		WriteTimeout:                  connectTimeout,
		MaxResponseBodySize:           maxBodySize,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		ReadBufferSize:                8192,
		WriteBufferSize:               4096,
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
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		err := client.Do(req, resp)
		if err != nil {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			if attempt < maxRetries {
				time.Sleep(retryDelay * time.Duration(attempt+1))
			}
			continue
		}

		// Collect headers
		hdrs := make(map[string]string)
		resp.Header.VisitAll(func(key, value []byte) {
			hdrs[string(key)] = string(value)
		})

		body := string(resp.Body())
		size := len(resp.Body())
		finalURL := url
		// Follow redirects: check Location header
		if loc := resp.Header.Peek("Location"); len(loc) > 0 {
			finalURL = string(loc)
		}
		statusCode := resp.StatusCode()

		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)

		// Handle redirects (up to 3)
		if statusCode >= 300 && statusCode < 400 && finalURL != url {
			redirectResp := Fetch(client, finalURL, method, headers, 0, 0)
			if redirectResp != nil {
				return redirectResp
			}
		}

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
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	err := client.Do(req, resp)
	if err != nil {
		return nil, 0, err
	}

	// Copy body since we release resp
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
