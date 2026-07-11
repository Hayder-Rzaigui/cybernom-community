package ingester

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/hayderrzaigui/cybernom/internal/config"
	"github.com/hayderrzaigui/cybernom/internal/ingester/fetchers"
)

// AlertSink is implemented by whatever persists+routes a triggered alert.
// Decoupled from the ingester so storage/notification concerns don't leak
// into fetch/match logic.
type AlertSink interface {
	HandleMatch(ctx context.Context, item fetchers.Item, match MatchResult) error
}

// Engine schedules and runs all configured feed fetchers on independent
// intervals, evaluates ingested content against compiled keywords, and
// forwards hits to an AlertSink.
type Engine struct {
	log      *slog.Logger
	matcher  *SafeMatcher
	keywords []*CompiledKeyword
	sink     AlertSink

	feeds     []scheduledFeed
	torClient *http.Client // nil if no onion feeds configured

	wg sync.WaitGroup

	// cancel is written once by Run (from the goroutine Run executes on)
	// and read by Shutdown, which is typically called from a different
	// goroutine (main.go launches Run via `go ingestEngine.Run(ctx)` and
	// later calls Shutdown from the goroutine that was waiting on the
	// shutdown signal/errCh). Without synchronization that's a data race
	// on the cancel field itself — benign in the common case where Run
	// has already set it by the time Shutdown is called, but not
	// guaranteed by the language, and exactly the kind of thing `go test
	// -race` flags. cancelMu makes both the write and the read safe
	// regardless of scheduling.
	cancelMu sync.Mutex
	cancel   context.CancelFunc
}

type scheduledFeed struct {
	fetcher      fetchers.Fetcher
	name         string
	pollInterval time.Duration
}

// NewEngine constructs the engine and eagerly compiles all keywords and
// fetchers. It returns an error rather than deferring failures to runtime —
// a bad keyword regex or malformed feed config should fail startup, not
// fail silently at 3am.
func NewEngine(cfg *config.Config, log *slog.Logger, sink AlertSink) (*Engine, error) {
	matcher := NewSafeMatcher(
		cfg.RegexSafety.MaxPatternLength,
		cfg.RegexSafety.MaxInputLength,
		cfg.RegexSafety.CompileTimeout,
		cfg.RegexSafety.ExecTimeout,
	)

	compiled := make([]*CompiledKeyword, 0, len(cfg.Keywords))
	for _, kw := range cfg.Keywords {
		ck, err := matcher.Compile(kw.Name, kw.Pattern, kw.Severity, kw.Tags, kw.IsRegex, kw.CaseSensitive)
		if err != nil {
			return nil, fmt.Errorf("compiling keyword %q: %w", kw.Name, err)
		}
		compiled = append(compiled, ck)
	}

	e := &Engine{
		log:      log,
		matcher:  matcher,
		keywords: compiled,
		sink:     sink,
	}

	var torClient *http.Client
	needsTor := false
	for _, f := range cfg.Feeds {
		if f.Enabled && f.Type == config.FeedTypeOnion {
			needsTor = true
			break
		}
	}
	if needsTor {
		client, err := fetchers.NewTorHTTPClient(cfg.Tor.ProxyAddress, cfg.Tor.DialTimeout)
		if err != nil {
			return nil, fmt.Errorf("configuring tor client: %w", err)
		}
		torClient = client
	}
	e.torClient = torClient

	for _, f := range cfg.Feeds {
		if !f.Enabled {
			continue
		}
		fetcher, err := buildFetcher(f, torClient)
		if err != nil {
			return nil, fmt.Errorf("building fetcher for feed %q: %w", f.Name, err)
		}
		interval := f.PollInterval
		if interval <= 0 {
			interval = 15 * time.Minute
		}
		e.feeds = append(e.feeds, scheduledFeed{fetcher: fetcher, name: f.Name, pollInterval: interval})
	}

	return e, nil
}

func buildFetcher(f config.Feed, torClient *http.Client) (fetchers.Fetcher, error) {
	const defaultTimeout = 30 * time.Second
	switch f.Type {
	case config.FeedTypeRSS:
		return fetchers.NewRSSFetcher(f.Name, f.URL, defaultTimeout), nil
	case config.FeedTypeWebsite:
		return fetchers.NewWebsiteFetcher(f.Name, f.URL, defaultTimeout), nil
	case config.FeedTypeAPI:
		return fetchers.NewAPIFetcher(f.Name, f.URL, f.APIMethod, f.APIAuthHeader, f.APIAuthEnvVar, f.APIDataPath, defaultTimeout), nil
	case config.FeedTypeOnion:
		if torClient == nil {
			return nil, fmt.Errorf("feed type onion requires tor client but none was configured")
		}
		// .onion fetches get a longer timeout — Tor circuits are slower.
		return fetchers.NewOnionFetcher(f.Name, f.URL, torClient)
	default:
		return nil, fmt.Errorf("unknown feed type %q", f.Type)
	}
}

// Run starts one scheduling goroutine per feed and blocks until ctx is
// cancelled, then waits for in-flight fetches to finish (graceful
// shutdown — no fetch is abandoned mid-write to storage).
func (e *Engine) Run(ctx context.Context) {
	runCtx, cancel := context.WithCancel(ctx)
	e.cancelMu.Lock()
	e.cancel = cancel
	e.cancelMu.Unlock()

	e.log.Info("ingester engine starting", "feeds", len(e.feeds), "keywords", len(e.keywords))

	for _, sf := range e.feeds {
		e.wg.Add(1)
		go e.runFeedLoop(runCtx, sf)
	}

	<-runCtx.Done()
	e.log.Info("ingester engine shutting down, waiting for in-flight fetches")
	e.wg.Wait()
	e.log.Info("ingester engine stopped")
}

// Shutdown cancels all scheduling loops. Safe to call once, and safe to
// call even if Run hasn't yet reached the point of setting e.cancel — in
// that narrow window Shutdown is a no-op, but Run's runCtx is still
// derived from the ctx passed to it (main.go's signal-driven root
// context), so runFeedLoop's goroutines still observe ctx.Done() and
// exit; nothing is left running.
func (e *Engine) Shutdown() {
	e.cancelMu.Lock()
	cancel := e.cancel
	e.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (e *Engine) runFeedLoop(ctx context.Context, sf scheduledFeed) {
	defer e.wg.Done()

	// Immediate first run, then tick on interval.
	e.fetchOnce(ctx, sf)

	ticker := time.NewTicker(sf.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.fetchOnce(ctx, sf)
		}
	}
}

func (e *Engine) fetchOnce(ctx context.Context, sf scheduledFeed) {
	fetchCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	items, err := sf.fetcher.Fetch(fetchCtx)
	if err != nil {
		e.log.Warn("feed fetch failed", "feed", sf.name, "error", err)
		return
	}

	e.log.Debug("feed fetch succeeded", "feed", sf.name, "items", len(items))

	for _, item := range items {
		matches := e.matcher.Match(fetchCtx, item.Title+"\n"+item.Content, e.keywords)
		for _, match := range matches {
			if err := e.sink.HandleMatch(fetchCtx, item, match); err != nil {
				e.log.Error("alert sink failed to handle match", "feed", sf.name, "keyword", match.Keyword, "error", err)
			}
		}
	}
}
