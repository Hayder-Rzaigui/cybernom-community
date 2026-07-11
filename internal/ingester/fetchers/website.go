package fetchers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// WebsiteFetcher does a lightweight fetch-and-extract of a plain web page:
// it strips script/style blocks and HTML tags to produce searchable text.
// It deliberately does NOT execute JavaScript (no headless browser) —
// that's a conscious scope boundary: running a full browser engine against
// arbitrary/untrusted sites, including scraping targets that may be
// adversarial, meaningfully increases attack surface (browser CVEs,
// resource exhaustion) for a feature most threat-intel sources don't need
// (target pages are typically static blogs/advisories/forums).
type WebsiteFetcher struct {
	Name       string
	URL        string
	httpClient *http.Client
}

func NewWebsiteFetcher(name, url string, timeout time.Duration) *WebsiteFetcher {
	return &WebsiteFetcher{
		Name:       name,
		URL:        url,
		httpClient: NewHTTPClient(timeout),
	}
}

var (
	scriptStyleRe = regexp.MustCompile(`(?is)<(script|style)[^>]*>.*?</(script|style)>`)
	tagRe         = regexp.MustCompile(`(?s)<[^>]+>`)
	titleRe       = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	whitespaceRe  = regexp.MustCompile(`\s+`)
)

func (f *WebsiteFetcher) Fetch(ctx context.Context) ([]Item, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("website[%s]: building request: %w", f.Name, err)
	}
	setCommonHeaders(req)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("website[%s]: fetching: %w", f.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("website[%s]: unexpected status %d", f.Name, resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxResponseBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("website[%s]: reading body: %w", f.Name, err)
	}

	html := string(body)
	title := extractTitle(html)
	text := extractText(html)

	return []Item{{
		Title:       title,
		Content:     text,
		URL:         f.URL,
		PublishedAt: time.Now(),
		SourceFeed:  f.Name,
	}}, nil
}

func extractTitle(html string) string {
	m := titleRe.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(whitespaceRe.ReplaceAllString(m[1], " "))
}

func extractText(html string) string {
	noScripts := scriptStyleRe.ReplaceAllString(html, " ")
	noTags := tagRe.ReplaceAllString(noScripts, " ")
	return strings.TrimSpace(whitespaceRe.ReplaceAllString(noTags, " "))
}
