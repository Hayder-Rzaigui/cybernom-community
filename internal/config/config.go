// Package config loads and validates CyberNom's runtime configuration.
//
// Precedence (highest wins): environment variables > config.yaml > defaults.
// Secrets (DB password, JWT signing key, SMTP password, webhook URLs) are
// expected via environment variables in production; the YAML file is for
// structural/non-secret configuration (feed definitions, intervals, etc).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FeedType enumerates the supported ingestion sources.
type FeedType string

const (
	FeedTypeRSS     FeedType = "rss"
	FeedTypeWebsite FeedType = "website"
	FeedTypeAPI     FeedType = "api"
	FeedTypeOnion   FeedType = "onion"
)

// Feed describes a single monitored source.
type Feed struct {
	Name           string        `yaml:"name"`
	Type           FeedType      `yaml:"type"`
	URL            string        `yaml:"url"`
	Enabled        bool          `yaml:"enabled"`
	PollInterval   time.Duration `yaml:"poll_interval"`
	Tags           []string      `yaml:"tags"`
	RequireTor     bool          `yaml:"require_tor"` // hard-enforced for .onion regardless of this flag
	APIMethod      string        `yaml:"api_method,omitempty"`
	APIAuthHeader  string        `yaml:"api_auth_header,omitempty"`
	APIAuthEnvVar  string        `yaml:"api_auth_env_var,omitempty"` // token pulled from env, never stored in YAML
	APIDataPath    string        `yaml:"api_data_path,omitempty"`
}

// Keyword describes a single alerting rule evaluated against ingested content.
type Keyword struct {
	Name          string `yaml:"name"`
	Pattern       string `yaml:"pattern"`        // literal text OR regex, see IsRegex
	IsRegex       bool   `yaml:"is_regex"`
	CaseSensitive bool   `yaml:"case_sensitive"`
	Severity      string `yaml:"severity"` // low|medium|high|critical
	Tags          []string `yaml:"tags"`
}

// TorConfig configures the SOCKS5 proxy used exclusively for .onion feeds.
type TorConfig struct {
	ProxyAddress string        `yaml:"proxy_address"` // e.g. tor:9050
	DialTimeout  time.Duration `yaml:"dial_timeout"`
}

// GraphConfig configures the Microsoft Graph read-only collector (Vigil365 lineage).
// Every scope requested by CyberNom MUST end in ".Read.All" — enforced at
// startup by Validate().
type GraphConfig struct {
	Enabled      bool     `yaml:"enabled"`
	TenantID     string   `yaml:"tenant_id"`
	ClientID     string   `yaml:"client_id"`
	ClientSecretEnvVar string `yaml:"client_secret_env_var"` // e.g. CYBERNOM_GRAPH_CLIENT_SECRET
	Scopes       []string `yaml:"scopes"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// NotificationChannel is a single outbound alert sink.
type NotificationChannel struct {
	Type           string `yaml:"type"` // discord|slack|telegram|email|webhook
	Enabled        bool   `yaml:"enabled"`
	MinSeverity    string `yaml:"min_severity"`
	WebhookEnvVar  string `yaml:"webhook_env_var,omitempty"`
	BotTokenEnvVar string `yaml:"bot_token_env_var,omitempty"` // telegram only
	ChatIDEnvVar   string `yaml:"chat_id_env_var,omitempty"`   // telegram only
	SMTP           *SMTPConfig `yaml:"smtp,omitempty"`
}

// SMTPConfig configures the email notification sink.
type SMTPConfig struct {
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	Username       string `yaml:"username"`
	PasswordEnvVar string `yaml:"password_env_var"`
	From           string `yaml:"from"`
	To             []string `yaml:"to"`
	UseTLS         bool   `yaml:"use_tls"`
}

// AuthConfig configures the built-in JWT authentication layer.
type AuthConfig struct {
	JWTSigningKeyEnvVar string        `yaml:"jwt_signing_key_env_var"`
	AccessTokenTTL      time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL     time.Duration `yaml:"refresh_token_ttl"`
	BcryptCost          int           `yaml:"bcrypt_cost"`
}

// DatabaseConfig configures the Postgres connection.
type DatabaseConfig struct {
	Host            string `yaml:"host"`
	Port            int    `yaml:"port"`
	Name            string `yaml:"name"`
	User            string `yaml:"user"`
	PasswordEnvVar  string `yaml:"password_env_var"`
	SSLMode         string `yaml:"ssl_mode"`
	MaxOpenConns    int    `yaml:"max_open_conns"`
}

// ServerConfig configures the HTTP API server.
type ServerConfig struct {
	ListenAddress   string        `yaml:"listen_address"` // default 127.0.0.1:8080 — NOT 0.0.0.0
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
	RateLimitRPS    float64       `yaml:"rate_limit_rps"`
	TrustProxyHeaders bool        `yaml:"trust_proxy_headers"` // only enable behind a configured reverse proxy
}

// RegexSafety configures defense-in-depth limits on user-supplied regex,
// layered on top of Go's inherently linear-time RE2 engine (see docs/THREAT_MODEL.md).
type RegexSafety struct {
	MaxPatternLength int           `yaml:"max_pattern_length"`
	MaxInputLength   int           `yaml:"max_input_length"`
	CompileTimeout   time.Duration `yaml:"compile_timeout"`
	ExecTimeout      time.Duration `yaml:"exec_timeout"`
}

// Config is the root configuration object.
type Config struct {
	Server       ServerConfig           `yaml:"server"`
	Database     DatabaseConfig         `yaml:"database"`
	Auth         AuthConfig             `yaml:"auth"`
	Tor          TorConfig              `yaml:"tor"`
	Graph        GraphConfig            `yaml:"graph"`
	RegexSafety  RegexSafety            `yaml:"regex_safety"`
	Feeds        []Feed                 `yaml:"feeds"`
	Keywords     []Keyword              `yaml:"keywords"`
	Notifications []NotificationChannel `yaml:"notifications"`
}

// Load reads a YAML config file, applies defaults, overlays environment
// variables, and validates the result. It never returns a Config with
// plaintext secrets embedded from YAML — secrets are env-var only.
func Load(path string) (*Config, error) {
	cfg := defaults()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: reading %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parsing %s: %w", path, err)
		}
	}

	applyEnvOverrides(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validation failed: %w", err)
	}

	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddress:     "127.0.0.1:8080",
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			ShutdownTimeout:   10 * time.Second,
			RateLimitRPS:      5,
			TrustProxyHeaders: false,
		},
		Database: DatabaseConfig{
			Host:           "localhost",
			Port:           5432,
			Name:           "cybernom",
			User:           "cybernom",
			PasswordEnvVar: "CYBERNOM_DB_PASSWORD",
			SSLMode:        "prefer",
			MaxOpenConns:   10,
		},
		Auth: AuthConfig{
			JWTSigningKeyEnvVar: "CYBERNOM_JWT_SIGNING_KEY",
			AccessTokenTTL:      15 * time.Minute,
			RefreshTokenTTL:     7 * 24 * time.Hour,
			BcryptCost:          12,
		},
		Tor: TorConfig{
			ProxyAddress: "tor:9050",
			DialTimeout:  30 * time.Second,
		},
		RegexSafety: RegexSafety{
			MaxPatternLength: 512,
			MaxInputLength:   1 << 20, // 1 MiB
			CompileTimeout:   2 * time.Second,
			ExecTimeout:      2 * time.Second,
		},
	}
}

// applyEnvOverrides allows key operational settings to be overridden without
// touching YAML — mainly useful for container deployments.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("CYBERNOM_LISTEN_ADDRESS"); v != "" {
		cfg.Server.ListenAddress = v
	}
	if v := os.Getenv("CYBERNOM_DB_HOST"); v != "" {
		cfg.Database.Host = v
	}
	if v := os.Getenv("CYBERNOM_DB_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Database.Port = p
		}
	}
	if v := os.Getenv("CYBERNOM_TOR_PROXY"); v != "" {
		cfg.Tor.ProxyAddress = v
	}
	if v := os.Getenv("CYBERNOM_TRUST_PROXY_HEADERS"); v != "" {
		cfg.Server.TrustProxyHeaders = strings.EqualFold(v, "true")
	}
}

// Validate enforces CyberNom's non-negotiable security invariants. A
// misconfiguration here fails startup loudly rather than degrading silently.
func (c *Config) Validate() error {
	if os.Getenv(c.Auth.JWTSigningKeyEnvVar) == "" {
		return fmt.Errorf("JWT signing key env var %q is not set — refusing to start with no auth secret", c.Auth.JWTSigningKeyEnvVar)
	}
	if len(os.Getenv(c.Auth.JWTSigningKeyEnvVar)) < 32 {
		return fmt.Errorf("JWT signing key must be at least 32 bytes (256 bits); use `openssl rand -hex 32`")
	}
	if c.Auth.BcryptCost < 10 {
		return fmt.Errorf("bcrypt cost %d is below minimum safe cost (10)", c.Auth.BcryptCost)
	}

	if c.Graph.Enabled {
		if c.Graph.TenantID == "" || c.Graph.ClientID == "" {
			return fmt.Errorf("graph.enabled=true but tenant_id/client_id are not set")
		}
		if os.Getenv(c.Graph.ClientSecretEnvVar) == "" {
			return fmt.Errorf("graph client secret env var %q is not set", c.Graph.ClientSecretEnvVar)
		}
		for _, scope := range c.Graph.Scopes {
			// Write scopes are rejected first and explicitly, so the reason
			// for rejection is unambiguous and doesn't depend on this being
			// the second check in the loop.
			if strings.HasSuffix(scope, ".ReadWrite.All") {
				return fmt.Errorf("scope %q requests write access — CyberNom is a read-only visibility tool by design and refuses to request write scopes", scope)
			}
			if !strings.HasSuffix(scope, ".Read.All") {
				return fmt.Errorf("scope %q is not a recognized read-only scope; CyberNom enforces least-privilege and only accepts *.Read.All Graph scopes", scope)
			}
		}
	}

	for i, feed := range c.Feeds {
		if feed.Type == FeedTypeOnion && !strings.HasSuffix(feed.URL, ".onion") && !strings.Contains(feed.URL, ".onion/") {
			return fmt.Errorf("feed[%d] %q: type=onion but URL does not look like a .onion address", i, feed.Name)
		}
	}

	for i, kw := range c.Keywords {
		if kw.IsRegex && len(kw.Pattern) > c.RegexSafety.MaxPatternLength {
			return fmt.Errorf("keyword[%d] %q: pattern exceeds max_pattern_length (%d)", i, kw.Name, c.RegexSafety.MaxPatternLength)
		}
	}

	for i, ch := range c.Notifications {
		if !ch.Enabled {
			continue
		}
		switch ch.Type {
		case "telegram":
			if ch.BotTokenEnvVar == "" || ch.ChatIDEnvVar == "" {
				return fmt.Errorf("notification[%d] type=telegram is enabled but missing bot_token_env_var or chat_id_env_var", i)
			}
		case "email":
			// email's own required fields (SMTP host/port/etc) are
			// validated where SMTPConfig is parsed, not here.
		default:
			// discord, slack, and any other future webhook-style
			// channel all require webhook_env_var.
			if ch.WebhookEnvVar == "" {
				return fmt.Errorf("notification[%d] type=%s is enabled but has no webhook_env_var configured", i, ch.Type)
			}
		}
	}

	if c.Server.ListenAddress == "0.0.0.0:8080" {
		return fmt.Errorf("refusing to bind 0.0.0.0 by default — set listen_address explicitly and put a reverse proxy in front (see deployments/nginx)")
	}

	return nil
}
