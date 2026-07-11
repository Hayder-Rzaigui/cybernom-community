package auth

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestPeekUsername_ExtractsAndRestoresBody guards against the easiest way
// this middleware could break the login handler: consuming r.Body to read
// the username and never putting it back, which would make handleLogin see
// an empty body on every request once this middleware runs in front of it.
func TestPeekUsername_ExtractsAndRestoresBody(t *testing.T) {
	body := `{"username":"alice","password":"correct-horse-battery-staple"}`
	req, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error building request: %v", err)
	}

	got := peekUsername(req)
	if got != "alice" {
		t.Errorf("expected username %q, got %q", "alice", got)
	}

	// The handler downstream must still be able to read the full original
	// body — this is the part that's easy to get wrong with io.ReadAll.
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("unexpected error reading restored body: %v", err)
	}
	if string(restored) != body {
		t.Errorf("body was not preserved: got %q, want %q", restored, body)
	}
}

func TestPeekUsername_MalformedBodyReturnsEmpty(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("unexpected error building request: %v", err)
	}
	if got := peekUsername(req); got != "" {
		t.Errorf("expected empty username for malformed body, got %q", got)
	}
}

func TestPeekUsername_NilBodyReturnsEmpty(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	if err != nil {
		t.Fatalf("unexpected error building request: %v", err)
	}
	if got := peekUsername(req); got != "" {
		t.Errorf("expected empty username for nil body, got %q", got)
	}
}
