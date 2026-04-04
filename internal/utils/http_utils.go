package utils

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---- sync.Pool for body read buffers ----

var bodyPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 64*1024) // 64KB initial cap
		return &b
	},
}

func getBodyBuf() *[]byte {
	return bodyPool.Get().(*[]byte)
}

func putBodyBuf(b *[]byte) {
	*b = (*b)[:0]
	bodyPool.Put(b)
}

// ---- DNS cache ----

type dnsCacheEntry struct {
	addrs []string
	ts    time.Time
}

var (
	dnsCache    sync.Map
	dnsCacheTTL = 5 * time.Minute
)

func cachedDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		// Skip cache for IPs
		if net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		// Check cache
		if val, ok := dnsCache.Load(host); ok {
			entry := val.(*dnsCacheEntry)
			if time.Since(entry.ts) < dnsCacheTTL && len(entry.addrs) > 0 {
				// Use first cached addr
				return dialer.DialContext(ctx, network, net.JoinHostPort(entry.addrs[0], port))
			}
			dnsCache.Delete(host)
		}
		// Resolve and cache
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return dialer.DialContext(ctx, network, addr)
		}
		dnsCache.Store(host, &dnsCacheEntry{addrs: addrs, ts: time.Now()})
		return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0], port))
	}
}

// ---- HTTP Response ----

type HTTPResponse struct {
	URL     string
	Status  int
	Headers http.Header
	Body    string
	Size    int
}

const maxBodySize = 5 * 1024 * 1024 // 5MB

func NewHTTPClient(connectTimeout, readTimeout, totalTimeout time.Duration,
	maxConnsPerHost, totalLimit int) *http.Client {
	dialer := &net.Dialer{
		Timeout:   connectTimeout,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		// InsecureSkipVerify: scanning tool connecting to arbitrary hosts with self-signed/expired certs.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			SessionTicketsDisabled: false,
		},
		DialContext:           cachedDialContext(dialer),
		MaxIdleConns:          totalLimit,
		MaxIdleConnsPerHost:   maxConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: readTimeout,
		WriteBufferSize:       4096,
		ReadBufferSize:        8192,
		DisableCompression:    true, // avoid decompression overhead for scanning
		ForceAttemptHTTP2:     false, // HTTP/1.1 faster for mass scanning (no stream multiplexing overhead)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   totalTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func Fetch(client *http.Client, url, method string, headers map[string]string,
	maxRetries int, retryDelay time.Duration) *HTTPResponse {
	if method == "" {
		method = "GET"
	}
	for attempt := 0; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			cancel()
			continue
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			if attempt < maxRetries {
				time.Sleep(retryDelay * time.Duration(attempt+1))
			}
			continue
		}
		buf := getBodyBuf()
		*buf, err = io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()
		cancel()
		if err != nil {
			putBodyBuf(buf)
			if attempt < maxRetries {
				time.Sleep(retryDelay * time.Duration(attempt+1))
			}
			continue
		}
		body := string(*buf)
		size := len(*buf)
		putBodyBuf(buf)
		return &HTTPResponse{
			URL:    resp.Request.URL.String(),
			Status: resp.StatusCode,
			Headers: resp.Header,
			Body:   body,
			Size:   size,
		}
	}
	return nil
}

func FetchRaw(ctx context.Context, client *http.Client, url string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	return data, resp.StatusCode, err
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
