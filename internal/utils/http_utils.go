package utils

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type HTTPResponse struct {
	URL     string
	Status  int
	Headers http.Header
	Body    string
	Size    int
}

func NewHTTPClient(connectTimeout, readTimeout, totalTimeout time.Duration,
	maxConnsPerHost, totalLimit int) *http.Client {
	transport := &http.Transport{
		// InsecureSkipVerify: scanning tool connecting to arbitrary hosts with self-signed/expired certs.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        totalLimit,
		MaxIdleConnsPerHost: maxConnsPerHost,
		MaxConnsPerHost:     maxConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
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
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		resp.Body.Close()
		cancel()
		if err != nil {
			if attempt < maxRetries {
				time.Sleep(retryDelay * time.Duration(attempt+1))
			}
			continue
		}
		return &HTTPResponse{
			URL:     resp.Request.URL.String(),
			Status:  resp.StatusCode,
			Headers: resp.Header,
			Body:    string(bodyBytes),
			Size:    len(bodyBytes),
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
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
