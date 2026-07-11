package fetchers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

// Item is a single normalized piece of ingested content, regardless of
// which fetcher produced it.
type Item struct {
	Title       string
	Content     string
	URL         string
	PublishedAt time.Time
	SourceFeed  string
}

// Fetcher is implemented by every ingestion source type.
type Fetcher interface {
	// Fetch retrieves and normalizes the current items from a source. It
	// must respect ctx cancellation/deadline and must never follow
	// redirects to a different scheme/host without the caller's knowledge
	// (see NewHTTPClient).
	Fetch(ctx context.Context) ([]Item, error)
}

const (
	maxResponseBytes = 10 << 20 // 10 MiB hard cap per fetch, prevents memory exhaustion from a hostile/misbehaving source
	userAgent        = "CyberNom/1.0 (+https://github.com/hayderrzaigui/cybernom)"
)

// NewHTTPClient builds a hardened *http.Client for clearnet fetches
// (rss/website/api feed types). Key hardening points:
//   - explicit timeout (no hung connections holding worker goroutines forever)
//   - TLS min version 1.2
//   - bounded redirect count, and redirects are not followed across schemes
//     (mitigates SSRF-via-redirect to internal http:// resources)
func NewHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			if via[0].URL.Scheme != req.URL.Scheme {
				return fmt.Errorf("refusing cross-scheme redirect from %s to %s", via[0].URL.Scheme, req.URL.Scheme)
			}
			return nil
		},
	}
}

// NewTorHTTPClient builds an http.Client that routes exclusively through
// the configured Tor SOCKS5 proxy. Used ONLY for feed.type == "onion".
// There is deliberately no fallback path to clearnet if the Tor dial fails
// — a failed onion fetch must fail closed, never silently leak the request
// over clearnet.
func NewTorHTTPClient(socksProxyAddr string, timeout time.Duration) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", socksProxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("configuring tor socks5 dialer: %w", err)
	}

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("tor proxy dialer does not support context-aware dialing")
	}

	transport := &http.Transport{
		DialContext:     contextDialer.DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			// Onion redirects must stay onion — refuses a malicious hidden
			// service trying to bounce the crawler out to clearnet.
			if !isOnionHost(req.URL.Hostname()) {
				return fmt.Errorf("refusing redirect from .onion to non-onion host %s", req.URL.Hostname())
			}
			return nil
		},
	}, nil
}

func isOnionHost(host string) bool {
	const suffix = ".onion"
	return len(host) > len(suffix) && host[len(host)-len(suffix):] == suffix
}

func setCommonHeaders(req *http.Request) {
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
}
