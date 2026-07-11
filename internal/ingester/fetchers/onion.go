package fetchers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OnionFetcher fetches a .onion hidden service page, exclusively through
// Tor. The http.Client passed in MUST come from NewTorHTTPClient — this
// type takes an already-configured client rather than a proxy address
// specifically so that misconfiguration can't accidentally construct a
// clearnet client for an onion feed (fail-safe by construction, not by
// convention).
type OnionFetcher struct {
	Name       string
	URL        string
	torClient  *http.Client
}

// NewOnionFetcher requires a pre-built Tor-routed client. See
// fetchers.NewTorHTTPClient and ingester.go for wiring.
func NewOnionFetcher(name, url string, torClient *http.Client) (*OnionFetcher, error) {
	if !isOnionHost(hostnameOnly(url)) {
		return nil, fmt.Errorf("onion[%s]: URL %q does not appear to be a .onion address", name, url)
	}
	return &OnionFetcher{Name: name, URL: url, torClient: torClient}, nil
}

func (f *OnionFetcher) Fetch(ctx context.Context) ([]Item, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("onion[%s]: building request: %w", f.Name, err)
	}
	setCommonHeaders(req)

	resp, err := f.torClient.Do(req)
	if err != nil {
		// Fails closed: any error (including Tor circuit failure) surfaces
		// as a fetch error. There is no fallback client to retry on.
		return nil, fmt.Errorf("onion[%s]: fetching via tor: %w", f.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("onion[%s]: unexpected status %d", f.Name, resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxResponseBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("onion[%s]: reading body: %w", f.Name, err)
	}

	html := string(body)
	return []Item{{
		Title:       extractTitle(html),
		Content:     extractText(html),
		URL:         f.URL,
		PublishedAt: time.Now(),
		SourceFeed:  f.Name,
	}}, nil
}

func hostnameOnly(rawURL string) string {
	// Minimal, dependency-free host extraction sufficient for the .onion
	// suffix check; full parsing/validation happens via url.Parse in the
	// caller when the request is actually constructed.
	s := rawURL
	for _, prefix := range []string{"http://", "https://"} {
		if len(s) > len(prefix) && s[:len(prefix)] == prefix {
			s = s[len(prefix):]
			break
		}
	}
	for i, c := range s {
		if c == '/' || c == ':' {
			return s[:i]
		}
	}
	return s
}
