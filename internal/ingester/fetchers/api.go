package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// APIFetcher ingests a generic JSON API endpoint. DataPath is a simple
// dot-notation path (e.g. "data.results") to the array of records within
// the JSON response; TitleField/ContentField/URLField map record keys to
// the normalized Item fields.
type APIFetcher struct {
	Name          string
	URL           string
	Method        string
	AuthHeader    string
	AuthEnvVar    string // token is read from environment at fetch time, never persisted
	DataPath      string
	TitleField    string
	ContentField  string
	URLField      string
	httpClient    *http.Client
}

func NewAPIFetcher(name, url, method, authHeader, authEnvVar, dataPath string, timeout time.Duration) *APIFetcher {
	if method == "" {
		method = http.MethodGet
	}
	return &APIFetcher{
		Name:         name,
		URL:          url,
		Method:       method,
		AuthHeader:   authHeader,
		AuthEnvVar:   authEnvVar,
		DataPath:     dataPath,
		TitleField:   "title",
		ContentField: "description",
		URLField:     "url",
		httpClient:   NewHTTPClient(timeout),
	}
}

func (f *APIFetcher) Fetch(ctx context.Context) ([]Item, error) {
	req, err := http.NewRequestWithContext(ctx, f.Method, f.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("api[%s]: building request: %w", f.Name, err)
	}
	setCommonHeaders(req)
	req.Header.Set("Accept", "application/json")

	if f.AuthHeader != "" && f.AuthEnvVar != "" {
		token := os.Getenv(f.AuthEnvVar)
		if token == "" {
			return nil, fmt.Errorf("api[%s]: auth env var %q is not set", f.Name, f.AuthEnvVar)
		}
		req.Header.Set(f.AuthHeader, token)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api[%s]: fetching: %w", f.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api[%s]: unexpected status %d", f.Name, resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxResponseBytes)
	var raw interface{}
	if err := json.NewDecoder(limited).Decode(&raw); err != nil {
		return nil, fmt.Errorf("api[%s]: decoding json: %w", f.Name, err)
	}

	records, err := navigate(raw, f.DataPath)
	if err != nil {
		return nil, fmt.Errorf("api[%s]: %w", f.Name, err)
	}

	arr, ok := records.([]interface{})
	if !ok {
		return nil, fmt.Errorf("api[%s]: data_path %q did not resolve to an array", f.Name, f.DataPath)
	}

	items := make([]Item, 0, len(arr))
	for _, rec := range arr {
		m, ok := rec.(map[string]interface{})
		if !ok {
			continue
		}
		items = append(items, Item{
			Title:       stringField(m, f.TitleField),
			Content:     stringField(m, f.ContentField),
			URL:         stringField(m, f.URLField),
			PublishedAt: time.Now(),
			SourceFeed:  f.Name,
		})
	}
	return items, nil
}

// navigate walks dot-separated keys through a decoded JSON structure.
// Empty path returns the root value unchanged.
func navigate(root interface{}, path string) (interface{}, error) {
	if path == "" {
		return root, nil
	}
	cur := root
	for _, key := range strings.Split(path, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("data_path segment %q: parent is not an object", key)
		}
		next, exists := m[key]
		if !exists {
			return nil, fmt.Errorf("data_path segment %q: key not found", key)
		}
		cur = next
	}
	return cur, nil
}

func stringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
