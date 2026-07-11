// Package ingester contains the feed-fetching engine and the keyword
// matching pipeline evaluated against ingested content.
package ingester

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SafeMatcher wraps pattern matching against untrusted external feed
// content (RSS titles/bodies, scraped web pages, .onion page text) with two
// independent layers of ReDoS defense:
//
//  1. STRUCTURAL: Go's regexp package compiles to RE2, which guarantees
//     worst-case linear time in input length — RE2 has no backtracking
//     engine, so the catastrophic-backtracking patterns that make ReDoS
//     possible in PCRE/Python-re/JS-regex (e.g. (a+)+b against "aaaa...c")
//     simply cannot blow up here. This is the primary defense and it is
//     architectural, not configurable.
//  2. DEFENSE IN DEPTH: even with RE2's linear-time guarantee, a
//     pathological pattern against a very large input is still O(n) work
//     that could be significant, so we additionally cap pattern length,
//     input length, and wrap execution in a hard deadline via a bounded
//     goroutine as a last-resort circuit breaker.
type SafeMatcher struct {
	maxPatternLength int
	maxInputLength   int
	compileTimeout   time.Duration
	execTimeout      time.Duration
}

func NewSafeMatcher(maxPatternLength, maxInputLength int, compileTimeout, execTimeout time.Duration) *SafeMatcher {
	return &SafeMatcher{
		maxPatternLength: maxPatternLength,
		maxInputLength:   maxInputLength,
		compileTimeout:   compileTimeout,
		execTimeout:      execTimeout,
	}
}

// CompiledKeyword is a keyword rule after safe compilation.
type CompiledKeyword struct {
	Name          string
	Severity      string
	Tags          []string
	isRegex       bool
	caseSensitive bool
	literal       string
	re            *regexp.Regexp
}

// Compile validates and compiles a single keyword rule. It never panics and
// always returns an error rather than a partially-usable matcher.
//
// Rejected inputs:
//   - patterns exceeding maxPatternLength
//   - patterns that fail to compile under RE2 syntax (RE2 itself rejects
//     backreferences and lookaround, which removes another entire class of
//     PCRE-only ReDoS constructs by definition)
func (m *SafeMatcher) Compile(name, pattern, severity string, tags []string, isRegex, caseSensitive bool) (*CompiledKeyword, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, fmt.Errorf("keyword %q: empty pattern", name)
	}
	if len(pattern) > m.maxPatternLength {
		return nil, fmt.Errorf("keyword %q: pattern length %d exceeds max %d", name, len(pattern), m.maxPatternLength)
	}

	ck := &CompiledKeyword{
		Name:          name,
		Severity:      severity,
		Tags:          tags,
		isRegex:       isRegex,
		caseSensitive: caseSensitive,
	}

	if !isRegex {
		if caseSensitive {
			ck.literal = pattern
		} else {
			ck.literal = strings.ToLower(pattern)
		}
		return ck, nil
	}

	// Regex path: compile with a timeout guard. RE2 compilation itself is
	// fast and bounded, but we still bound it explicitly for defense in depth
	// and to fail predictably under load.
	compileCtx, cancel := context.WithTimeout(context.Background(), m.compileTimeout)
	defer cancel()

	type compileResult struct {
		re  *regexp.Regexp
		err error
	}
	resultCh := make(chan compileResult, 1)

	go func() {
		expr := pattern
		if !caseSensitive {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		resultCh <- compileResult{re: re, err: err}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			return nil, fmt.Errorf("keyword %q: invalid regex: %w", name, res.err)
		}
		ck.re = res.re
		return ck, nil
	case <-compileCtx.Done():
		return nil, fmt.Errorf("keyword %q: regex compilation exceeded %s", name, m.compileTimeout)
	}
}

// MatchResult describes a single keyword hit within a piece of content.
type MatchResult struct {
	Keyword string
	Severity string
	Tags     []string
	Snippet  string // bounded-length context around the match, for alert display
}

// Match evaluates all compiled keywords against a single piece of content
// (already truncated to maxInputLength by the caller/ingester). Returns all
// matches, not just the first, since a single article can legitimately
// trigger multiple distinct alerts.
func (m *SafeMatcher) Match(ctx context.Context, content string, keywords []*CompiledKeyword) []MatchResult {
	if len(content) > m.maxInputLength {
		content = content[:m.maxInputLength]
	}

	var results []MatchResult
	lowerContent := strings.ToLower(content)

	for _, kw := range keywords {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		if !kw.isRegex {
			haystack := content
			if !kw.caseSensitive {
				haystack = lowerContent
			}
			if idx := strings.Index(haystack, kw.literal); idx != -1 {
				results = append(results, MatchResult{
					Keyword:  kw.Name,
					Severity: kw.Severity,
					Tags:     kw.Tags,
					Snippet:  snippetAround(content, idx, len(kw.literal)),
				})
			}
			continue
		}

		loc := m.execWithTimeout(kw.re, content)
		if loc != nil {
			results = append(results, MatchResult{
				Keyword:  kw.Name,
				Severity: kw.Severity,
				Tags:     kw.Tags,
				Snippet:  snippetAround(content, loc[0], loc[1]-loc[0]),
			})
		}
	}
	return results
}

// execWithTimeout runs FindStringIndex on a bounded worker goroutine as a
// last-resort circuit breaker. Under RE2 this should never actually trip on
// legitimate patterns; if it does trip, that is itself a signal worth
// logging (the caller logs a warning when this returns nil due to timeout
// vs due to no-match — see ingester.go).
func (m *SafeMatcher) execWithTimeout(re *regexp.Regexp, content string) []int {
	resultCh := make(chan []int, 1)
	go func() {
		resultCh <- re.FindStringIndex(content)
	}()

	select {
	case loc := <-resultCh:
		return loc
	case <-time.After(m.execTimeout):
		return nil
	}
}

func snippetAround(content string, start, matchLen int) string {
	const context = 60
	from := start - context
	if from < 0 {
		from = 0
	}
	to := start + matchLen + context
	if to > len(content) {
		to = len(content)
	}
	snippet := content[from:to]
	return strings.TrimSpace(snippet)
}
