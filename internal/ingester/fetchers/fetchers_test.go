package fetchers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hayderrzaigui/cybernom/internal/ingester/fetchers"
)

func TestWebsiteFetcher_ExtractsTitleAndStripsMarkup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Test Advisory</title><style>.x{color:red}</style></head>
			<body><script>alert(1)</script><p>A critical vulnerability was disclosed.</p></body></html>`))
	}))
	defer server.Close()

	f := fetchers.NewWebsiteFetcher("test-site", server.URL, 5*time.Second)
	items, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	item := items[0]
	if item.Title != "Test Advisory" {
		t.Errorf("expected title 'Test Advisory', got %q", item.Title)
	}
	if strings.Contains(item.Content, "<script>") || strings.Contains(item.Content, "alert(1)") {
		t.Errorf("expected script content to be stripped, got: %q", item.Content)
	}
	if strings.Contains(item.Content, "color:red") {
		t.Errorf("expected style content to be stripped, got: %q", item.Content)
	}
	if !strings.Contains(item.Content, "critical vulnerability was disclosed") {
		t.Errorf("expected body text to be preserved, got: %q", item.Content)
	}
}

func TestWebsiteFetcher_RejectsNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	f := fetchers.NewWebsiteFetcher("broken-site", server.URL, 5*time.Second)
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

// TestNewOnionFetcher_RejectsNonOnionURL guards the fail-safe construction
// property described in docs/THREAT_MODEL.md (T6): a feed configured as
// type=onion must actually target a .onion address, or construction fails
// before any network activity happens.
func TestNewOnionFetcher_RejectsNonOnionURL(t *testing.T) {
	dummyClient := &http.Client{}
	_, err := fetchers.NewOnionFetcher("bad-onion-feed", "https://clearnet-example.com", dummyClient)
	if err == nil {
		t.Fatal("expected error when constructing an onion fetcher with a non-.onion URL")
	}
}

func TestNewOnionFetcher_AcceptsOnionURL(t *testing.T) {
	dummyClient := &http.Client{}
	_, err := fetchers.NewOnionFetcher("valid-onion-feed", "http://exampleoniondomainxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion", dummyClient)
	if err != nil {
		t.Fatalf("unexpected error constructing valid onion fetcher: %v", err)
	}
}
