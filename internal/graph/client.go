// Package graph implements a strictly read-only Microsoft Graph collector
// for M365 security signals (risky sign-ins, security alerts, directory
// role assignments, etc.). This is the Vigil365-lineage component of
// CyberNom.
//
// Least-privilege by construction: config.Validate() refuses to start if
// any configured scope is not a *.Read.All scope, and this package never
// issues a write request (PATCH/POST/PUT/DELETE) to Graph — only GET.
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const graphBaseURL = "https://graph.microsoft.com/v1.0"
const tokenURLFmt = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"

// Client is a read-only Microsoft Graph client using the OAuth2 client
// credentials flow (application permissions, not delegated — appropriate
// for an unattended monitoring service).
type Client struct {
	tenantID           string
	clientID           string
	clientSecretEnvVar string
	scopes             []string
	httpClient         *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

func NewClient(tenantID, clientID, clientSecretEnvVar string, scopes []string) *Client {
	return &Client{
		tenantID:           tenantID,
		clientID:           clientID,
		clientSecretEnvVar: clientSecretEnvVar,
		scopes:             scopes,
		httpClient:         &http.Client{Timeout: 30 * time.Second},
	}
}

// SecurityAlert is a normalized subset of Graph's /security/alerts_v2 shape.
type SecurityAlert struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Category    string    `json:"category"`
	CreatedAt   time.Time `json:"createdDateTime"`
}

// RiskySignIn is a normalized subset of Graph's /identityProtection/riskyUsers shape.
type RiskySignIn struct {
	ID          string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	RiskLevel   string `json:"riskLevel"`
	RiskState   string `json:"riskState"`
}

// token performs (and caches) the client-credentials token acquisition.
// Tokens are cached in memory only, refreshed 60s before expiry, and never
// written to disk or logged.
func (c *Client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && time.Now().Before(c.expiresAt.Add(-60*time.Second)) {
		return c.accessToken, nil
	}

	secret := os.Getenv(c.clientSecretEnvVar)
	if secret == "" {
		return "", fmt.Errorf("graph: client secret env var %q not set", c.clientSecretEnvVar)
	}

	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", secret)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", strings.Join(c.scopes, " "))

	tokenURL := fmt.Sprintf(tokenURLFmt, c.tenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("graph: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("graph: requesting token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Deliberately do not include the response body in the error — it
		// can contain sensitive diagnostic info from AAD in some failure modes.
		return "", fmt.Errorf("graph: token endpoint returned status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("graph: decoding token response: %w", err)
	}

	c.accessToken = tokenResp.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	return c.accessToken, nil
}

// get issues a read-only GET against a Graph endpoint. This is the only
// HTTP verb this package uses — enforced structurally, there is no
// generic "do" method that accepts an arbitrary verb.
func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	token, err := c.token(ctx)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, graphBaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("graph: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("graph: request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("graph: %s returned status %d", path, resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, 10<<20)
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return fmt.Errorf("graph: decoding response from %s: %w", path, err)
	}
	return nil
}

// ListSecurityAlerts fetches recent security alerts (read-only:
// SecurityAlert.Read.All).
func (c *Client) ListSecurityAlerts(ctx context.Context, top int) ([]SecurityAlert, error) {
	var page struct {
		Value []SecurityAlert `json:"value"`
	}
	path := fmt.Sprintf("/security/alerts_v2?$top=%d&$orderby=createdDateTime desc", top)
	if err := c.get(ctx, path, &page); err != nil {
		return nil, fmt.Errorf("listing security alerts: %w", err)
	}
	return page.Value, nil
}

// ListRiskySignIns fetches current risky user entries (read-only:
// IdentityRiskyUser.Read.All).
func (c *Client) ListRiskySignIns(ctx context.Context, top int) ([]RiskySignIn, error) {
	var page struct {
		Value []RiskySignIn `json:"value"`
	}
	path := fmt.Sprintf("/identityProtection/riskyUsers?$top=%d", top)
	if err := c.get(ctx, path, &page); err != nil {
		return nil, fmt.Errorf("listing risky sign-ins: %w", err)
	}
	return page.Value, nil
}
