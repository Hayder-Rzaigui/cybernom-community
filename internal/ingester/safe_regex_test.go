package ingester_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hayderrzaigui/cybernom/internal/ingester"
)

func newTestMatcher() *ingester.SafeMatcher {
	return ingester.NewSafeMatcher(
		512,             // maxPatternLength
		1<<20,           // maxInputLength
		2*time.Second,   // compileTimeout
		2*time.Second,   // execTimeout
	)
}

func TestCompile_LiteralKeyword(t *testing.T) {
	m := newTestMatcher()
	ck, err := m.Compile("ransomware", "ransomware", "high", []string{"malware"}, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ck.Name != "ransomware" {
		t.Errorf("expected name 'ransomware', got %q", ck.Name)
	}
}

func TestCompile_ValidRegex(t *testing.T) {
	m := newTestMatcher()
	_, err := m.Compile("cve", `CVE-\d{4}-\d{4,7}`, "critical", nil, true, false)
	if err != nil {
		t.Fatalf("expected valid regex to compile, got error: %v", err)
	}
}

func TestCompile_RejectsOversizedPattern(t *testing.T) {
	m := ingester.NewSafeMatcher(10, 1<<20, 2*time.Second, 2*time.Second)
	_, err := m.Compile("too-long", "this pattern is definitely longer than ten characters", "low", nil, false, false)
	if err == nil {
		t.Fatal("expected error for oversized pattern, got nil")
	}
}

func TestCompile_RejectsEmptyPattern(t *testing.T) {
	m := newTestMatcher()
	_, err := m.Compile("empty", "   ", "low", nil, false, false)
	if err == nil {
		t.Fatal("expected error for empty pattern, got nil")
	}
}

func TestCompile_RejectsInvalidRegexSyntax(t *testing.T) {
	m := newTestMatcher()
	_, err := m.Compile("bad", "(unclosed", "low", nil, true, false)
	if err == nil {
		t.Fatal("expected error for invalid regex syntax, got nil")
	}
}

// TestCompile_RejectsBackreferences documents an important structural
// property: RE2 does not support backreferences at all, which removes a
// whole class of PCRE-only ReDoS constructs by making them fail to compile
// rather than something we have to detect and block ourselves.
func TestCompile_RejectsBackreferences(t *testing.T) {
	m := newTestMatcher()
	_, err := m.Compile("backref", `(\w+)\s+\1`, "low", nil, true, false)
	if err == nil {
		t.Fatal("expected backreference pattern to fail RE2 compilation, but it succeeded")
	}
}

func TestMatch_LiteralCaseInsensitive(t *testing.T) {
	m := newTestMatcher()
	ck, err := m.Compile("ransomware", "RANSOMWARE", "high", []string{"malware"}, false, false)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	results := m.Match(context.Background(), "A new ransomware strain was observed today.", []*ingester.CompiledKeyword{ck})
	if len(results) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results))
	}
	if results[0].Keyword != "ransomware" {
		t.Errorf("expected keyword name 'ransomware', got %q", results[0].Keyword)
	}
}

func TestMatch_RegexMultipleKeywords(t *testing.T) {
	m := newTestMatcher()
	cve, _ := m.Compile("cve", `CVE-\d{4}-\d{4,7}`, "critical", nil, true, false)
	zeroDay, _ := m.Compile("zero-day", "zero-day", "critical", nil, false, false)

	content := "Researchers disclosed a zero-day tracked as CVE-2026-12345 affecting the product."
	results := m.Match(context.Background(), content, []*ingester.CompiledKeyword{cve, zeroDay})

	if len(results) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(results), results)
	}
}

func TestMatch_NoFalsePositive(t *testing.T) {
	m := newTestMatcher()
	ck, _ := m.Compile("ransomware", "ransomware", "high", nil, false, false)

	results := m.Match(context.Background(), "This article is about firewall best practices.", []*ingester.CompiledKeyword{ck})
	if len(results) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(results))
	}
}

// TestMatch_LinearTimeOnPathologicalInput is the core ReDoS regression
// test. It uses an input shape that is the textbook trigger for
// catastrophic backtracking in a PCRE-style engine — a long run of
// characters followed by a non-matching terminator against a pattern with
// nested quantifiers — and asserts it completes near-instantly under Go's
// RE2 engine rather than hanging or timing out.
func TestMatch_LinearTimeOnPathologicalInput(t *testing.T) {
	m := newTestMatcher()
	// Nested-quantifier pattern that is a classic ReDoS trigger in PCRE.
	ck, err := m.Compile("pathological", `(a+)+b`, "low", nil, true, false)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	// 40 'a's followed by a non-matching character — would take a PCRE
	// engine an astronomically long time (2^40+ steps); RE2 handles it in
	// microseconds because it never backtracks.
	pathologicalInput := strings.Repeat("a", 40) + "c"

	start := time.Now()
	results := m.Match(context.Background(), pathologicalInput, []*ingester.CompiledKeyword{ck})
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Fatalf("match took %s, expected near-instant completion under RE2 (no backtracking)", elapsed)
	}
	if len(results) != 0 {
		t.Fatalf("expected no match (input has no 'b'), got %d matches", len(results))
	}
}

func TestMatch_RespectsMaxInputLength(t *testing.T) {
	m := ingester.NewSafeMatcher(512, 10, 2*time.Second, 2*time.Second) // maxInputLength=10
	ck, _ := m.Compile("needle", "needle", "low", nil, false, false)

	// "needle" appears only after byte 10, so truncation should prevent the match.
	content := "0123456789needle"
	results := m.Match(context.Background(), content, []*ingester.CompiledKeyword{ck})
	if len(results) != 0 {
		t.Fatalf("expected input to be truncated before the match, got %d matches", len(results))
	}
}
