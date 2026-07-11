-- CyberNom initial schema
-- Apply with: psql -f migrations/0001_init.sql, or via your preferred
-- migration tool (golang-migrate, goose, etc. — see README for CLI usage).

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alerts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keyword_name  TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    source_feed   TEXT NOT NULL,
    item_title    TEXT NOT NULL,
    item_url      TEXT NOT NULL,
    snippet       TEXT NOT NULL,
    tags          TEXT[] NOT NULL DEFAULT '{}',
    acknowledged  BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts (acknowledged) WHERE acknowledged = false;

CREATE TABLE IF NOT EXISTS graph_snapshots (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        TEXT NOT NULL CHECK (kind IN ('security_alert', 'risky_signin')),
    severity    TEXT,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_graph_snapshots_kind_created_at ON graph_snapshots (kind, created_at DESC);

-- Required for gen_random_uuid() on Postgres < 13; harmless no-op on 13+.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Audit log: records who viewed or acknowledged which alert, and from
-- where. Append-only by convention (no UPDATE/DELETE paths exist in
-- internal/storage) so it can serve as a record of who saw sensitive
-- content such as exposed credentials, not just a debugging aid.
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    username    TEXT NOT NULL,          -- denormalized so the trail survives user deletion
    action      TEXT NOT NULL CHECK (action IN ('alert.view', 'alert.ack', 'auth.login', 'auth.login_failed')),
    alert_id    UUID,                   -- NULL for actions not tied to a specific alert (e.g. login)
    ip_address  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_alert_id ON audit_log (alert_id) WHERE alert_id IS NOT NULL;

-- Shared, cross-replica login rate-limit counters. Keyed on an arbitrary
-- bucket key (e.g. "ip:1.2.3.4" or "user:alice") so the same table backs
-- both IP-based and username-based throttling. A fixed-window counter
-- (window_start + count) is sufficient here: login is low-frequency enough
-- that the extra precision of a sliding-window or token-bucket algorithm
-- isn't worth the added complexity, and resetting the window is a single
-- UPDATE. See internal/auth/ratelimit.go.
CREATE TABLE IF NOT EXISTS rate_limit_counters (
    bucket_key    TEXT PRIMARY KEY,
    window_start  TIMESTAMPTZ NOT NULL,
    count         INTEGER NOT NULL DEFAULT 0
);
