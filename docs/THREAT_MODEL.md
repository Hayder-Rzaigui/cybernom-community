# CyberNom Threat Model

This document describes the intended security posture; treat any gap
between this document and the code as a bug and please report it
(see `SECURITY.md`).

## 1. What CyberNom is, from a security perspective

CyberNom is a self-hosted service that (a) polls external and internal data
sources, (b) evaluates content against operator-defined rules, and (c)
notifies humans of matches. It handles three categories of sensitive
material:

1. **Credentials it holds**: DB password, JWT signing key, notification
   webhook URLs, SMTP password, Graph client secret.
2. **Data it collects**: M365 security posture data (via Graph) and
   threat-intel content (including, optionally, dark-web content via Tor).
3. **Access to itself**: who can read alerts, who can manage feeds/users.

## 2. Trust boundaries

```
                 ┌───────────────────────────────────────────────┐
                 │              Untrusted / External              │
                 │  RSS feeds · websites · JSON APIs · .onion      │
                 └───────────────────────┬───────────────────────┘
                                          │ HTTP(S) / SOCKS5-over-Tor
                                          ▼
┌──────────────┐      ┌────────────────────────────────┐      ┌───────────────┐
│  Operator /   │◄────►│      CyberNom (this repo)       │◄────►│  Postgres     │
│  Analyst      │ JWT  │  ingester · matcher · notifier  │ SQL  │  (internal    │
│  (browser/API)│ auth │  · graph collector · HTTP API   │ only │   network)    │
└──────────────┘      └───────────────┬──────────────────┘      └───────────────┘
                                       │ read-only OAuth2 (client credentials)
                                       ▼
                        ┌───────────────────────────┐
                        │   Microsoft Graph API      │
                        │   (*.Read.All scopes only) │
                        └───────────────────────────┘
```

The most important boundary is between **(1) untrusted feed content** and
**(2) everything else**. Feed content is attacker-influenced by definition —
a threat actor knows threat-intel tools scrape their forum posts and leak
site listings. CyberNom treats every byte from a feed as hostile input.

## 3. Threats and mitigations

### T1 — ReDoS via malicious feed content or a malicious keyword pattern
**Inherited from:** Threat-Intel-Nom-Nom (Python `re`, PCRE-style engine,
vulnerable to catastrophic backtracking).

**Mitigation:** CyberNom's keyword matcher (`internal/ingester/safe_regex.go`)
compiles all regex patterns with Go's standard `regexp` package, which is
backed by **RE2**. RE2 guarantees worst-case *linear* time in input length —
it has no backtracking engine, so constructs like `(a+)+b` cannot exhibit
exponential blowup, structurally, regardless of the input. This is not a
mitigation that can be misconfigured away; it's a property of the engine. As
defense in depth, we additionally cap pattern length, cap input length, and
wrap compilation/execution in timeouts as a circuit breaker.

RE2 also rejects backreferences and lookaround at compile time, which
removes an entire additional class of PCRE-only attack patterns by
definition (the pattern simply fails to compile).

### T2 — No authentication (both predecessor projects shipped with none)
**Mitigation:** Built-in JWT auth (`internal/auth`) with bcrypt-hashed
passwords (cost ≥ 10, enforced by config validation), short-lived access
tokens (default 15 min) plus longer-lived refresh tokens, and role-based
access control (`admin` / `viewer`). Login responses are constant-shape
(same error for "no such user" and "wrong password") to resist username
enumeration. This does **not** replace network-level isolation — see §4 —
it replaces relying on network isolation as the *only* control.

### T2b — Credential stuffing / brute force against login
**Gap this closes:** an in-memory, per-process, IP-only rate limiter has
two failure modes: it resets independently on every replica (an attacker
gets N× the effective attempts across N replicas), and being IP-only, it
does nothing against a distributed attack — many source IPs, one target
username — which is the more realistic shape of a real credential-stuffing
attempt.

**Mitigation:** `internal/auth/ratelimit.go` adds a `SharedRateLimiter`
backed by a Postgres fixed-window counter table (`rate_limit_counters`),
applied to `/api/v1/auth/login` in addition to (not instead of) the
existing in-memory limiter. It enforces two independent windows per
request — one keyed by client IP, one keyed by the attempted username, read
from the request body without disturbing it for the real handler. Either
limit tripping blocks the request. Because the counter lives in Postgres
rather than process memory, the limit holds even with multiple replicas
behind a load balancer. The limiter fails open on a database error (falls
through to the in-memory limiter and the handler) rather than locking out
every user because of a transient Postgres blip — availability of login
during a DB hiccup was judged more important than perfect enforcement
during that same hiccup.

### T3 — Secrets at rest
**Inherited gap:** neither predecessor encrypted webhook URLs, SMTP
passwords, or client secrets; Threat-Intel-Nom-Nom kept them in a `.env`
file with no additional protection.

**Mitigation:** CyberNom never stores secrets in the database or in
`config.yaml`. Every secret is read from an environment variable at the
point of use (see `config.go` — every `*_env_var` field) and is never
logged (the structured logger in `internal/logger` redacts any attribute
key containing `password`, `secret`, `token`, `webhook_url`, etc. as a
safety net). Operators are expected to supply these via their orchestrator's
secret store (Docker secrets, Kubernetes Secrets, Vault, etc.) rather than
plain `.env` files in production — the Compose example uses Docker secrets
for the DB password specifically to demonstrate this.

### T4 — SSRF via feed configuration or redirects
A malicious or compromised admin account (or a crafted redirect from a
legitimate feed) could attempt to make CyberNom fetch internal-network
resources.

**Mitigation:** The clearnet HTTP client refuses cross-scheme redirects and
caps redirect count at 5. The Tor client refuses any redirect that leaves
the `.onion` namespace — an .onion feed can never be used to pivot a
request to clearnet or to an internal address. Response bodies are capped
at 10 MiB to prevent memory-exhaustion via a hostile/misbehaving source.
Full network-layer SSRF protection (blocking RFC1918 destination IPs at the
dialer level) is on the roadmap — see the "Known Limitations" section
below; until then, run CyberNom's egress through an explicit egress proxy/
firewall rule if internal-network SSRF is in your threat model.

### T5 — Least-privilege violation against Microsoft Graph
**Inherited strength, made mandatory:** Vigil365 already followed a
read-only pattern; CyberNom enforces it at startup rather than by
convention. `config.Validate()` refuses to start if any configured Graph
scope does not end in `.Read.All`, and explicitly rejects any
`.ReadWrite.All` scope with a descriptive error. The `internal/graph`
package has no method that issues any HTTP verb other than GET.

### T6 — Onion feed accidentally leaking over clearnet
**New risk introduced by adding dark-web monitoring.** If a Tor circuit
fails, a naively-written client might silently retry over clearnet,
exposing the operator's real IP to a hostile hidden service operator.

**Mitigation:** `OnionFetcher` is constructed only from an already-built
Tor-routed `http.Client` — there is no code path that constructs a fallback
clearnet client for an onion feed. A Tor failure surfaces as a fetch error
and that poll cycle is skipped; it never falls back.

### T7 — Regex/DB injection from operator-supplied config
Feed and keyword definitions come from `config.yaml`, which is treated as
**operator-trusted, not attacker-trusted** — if an attacker can edit your
`config.yaml`, you have a much bigger problem than CyberNom. All *runtime*
user input (via the API — login, user creation, alert acknowledgement) goes
through parameterized SQL exclusively (`internal/storage/postgres.go`) and
JSON body size limits + `DisallowUnknownFields` decoding.

## 4. Defense in depth — network placement

Despite T2's mitigation, CyberNom still recommends:
- Binding the HTTP server to `127.0.0.1` (the default) and only exposing it
  via the bundled nginx reverse proxy (`deployments/nginx`), which
  terminates TLS and can add a second auth layer (HTTP Basic) in front of
  CyberNom's own JWT auth.
- Running Postgres and Tor with no host-published ports, reachable only
  from the internal Docker network (see `docker-compose.yml`).
- Treating `trust_proxy_headers: true` as safe **only** when you have
  verified the reverse proxy is the sole network path to CyberNom — this
  setting is what makes IP-based rate limiting trust `X-Forwarded-For`,
  which is otherwise trivially spoofable by a direct client.

## 5. Known limitations

- No SSRF protection at the network/DNS level (see T4) — CyberNom validates
  redirect behavior but does not currently block outbound requests to
  private IP ranges by IP inspection.
- No built-in secret rotation tooling — rotating the JWT signing key
  invalidates all outstanding tokens; there's no dual-key grace period yet.
- The ingester itself has no leader election — running multiple replicas
  will cause duplicate fetches against feeds. (Login rate limiting is now
  shared across replicas via `internal/auth/ratelimit.go`; see T2b below —
  this limitation is about the feed ingestion loop specifically, not auth.)
- No admin UI for user management yet — user creation beyond the initial
  bootstrap admin (`cybernom -init-admin`, see README) is API-only
  (`POST /api/v1/users`, admin role required).
- The audit log (`audit_log` table, `GET /api/v1/audit`) records alert
  views at list-call granularity, not per-alert-row granularity — a poll
  that returns 50 alerts produces one `alert.view` row, not 50. Sufficient
  to answer "did this user's session touch the alert feed and when," not
  "did this specific user definitely see this specific alert's content."
- The audit log has no tamper-evidence (no hash chaining, no WORM storage).
  A database-level admin or anyone with direct Postgres access could alter
  or delete rows. It is intended as an operational record for normal
  investigation, not as evidence that would survive a fully compromised
  database.
- `/dashboard`'s Content-Security-Policy allow-lists
  `https://cdnjs.cloudflare.com` in `script-src` so the dashboard can load
  Chart.js for the widget-grid donuts/line/bar charts. Every other route
  keeps `default-src 'none'`. This is a deliberate, narrow exception, not
  an oversight — but it does mean the dashboard's script integrity
  partially depends on cdnjs's availability and integrity rather than
  being fully self-contained. Self-hosting Chart.js under `/static/` and
  removing this allowance is the natural next step if that dependency
  becomes a concern; see the comment above `securityHeaders` in
  `internal/api/router.go`.
- The dashboard-metrics endpoint (`GET /api/v1/dashboard-metrics`) runs six
  aggregate queries per request, computed live rather than cached or
  materialized. Fine at the alert volumes this tool is designed for
  (hundreds to low thousands of open alerts); if that grows by orders of
  magnitude, consider a materialized view refreshed on a schedule instead
  of computing on every dashboard poll (every 20s per active session).
- SLA compliance (`sla_targets` table) is a fixed per-severity target
  configured at the database level, not per-keyword or per-customer. All
  alerts of a given severity share one target regardless of which keyword
  or source triggered them.

## 6. Reporting a vulnerability

See `SECURITY.md`.
