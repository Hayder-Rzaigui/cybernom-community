package fetchers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mmcdole/gofeed"
)

// RSSFetcher ingests standard RSS/Atom feeds.
type RSSFetcher struct {
	Name       string
	URL        string
	httpClient *http.Client
}

func NewRSSFetcher(name, url string, timeout time.Duration) *RSSFetcher {
	return &RSSFetcher{
		Name:       name,
		URL:        url,
		httpClient: NewHTTPClient(timeout),
	}
}

func (f *RSSFetcher) Fetch(ctx context.Context) ([]Item, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("rss[%s]: building request: %w", f.Name, err)
	}
	setCommonHeaders(req)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rss[%s]: fetching: %w", f.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rss[%s]: unexpected status %d", f.Name, resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxResponseBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("rss[%s]: reading body: %w", f.Name, err)
	}

	parser := gofeed.NewParser()
	feed, err := parser.ParseString(string(body))
	if err != nil {
		return nil, fmt.Errorf("rss[%s]: parsing feed: %w", f.Name, err)
	}

	items := make([]Item, 0, len(feed.Items))
	for _, entry := range feed.Items {
		published := time.Now()
		if entry.PublishedParsed != nil {
			published = *entry.PublishedParsed
		}
		items = append(items, Item{
			Title:       entry.Title,
			Content:     firstNonEmpty(entry.Content, entry.Description),
			URL:         entry.Link,
			PublishedAt: published,
			SourceFeed:  f.Name,
		})
	}
	return items, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
