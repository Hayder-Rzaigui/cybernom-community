-- CyberNom: database-driven threat feeds.
-- Apply after 0001_init.sql and 0002_dashboard_metrics.sql.
-- Applies to BOTH editions (Community and Enterprise) — feed management is
-- not an Enterprise-gated feature; only RBAC granularity, SIEM forwarding,
-- and the encrypted secrets vault are (see 0004_enterprise_rbac_siem.sql).
--
-- This file was split out of what was originally a single
-- 0003_enterprise_features.sql migration, specifically so a Community
-- deployment never has to run 0004's RBAC-widening statements (which
-- assume 4 role values a Community binary's roles_community.go never
-- writes) just to get one-click feed management, which both editions ship.

-- --- Threat feeds: replaces static config.yaml entries ---
--
-- Enables true one-click enable/disable from the admin UI: the ingester
-- engine polls this table for its feed list instead of (or in addition
-- to) config.yaml, so toggling `enabled` takes effect on the next
-- scheduling pass with no restart required.
CREATE TABLE IF NOT EXISTS threat_feeds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    feed_type       TEXT NOT NULL CHECK (feed_type IN ('rss', 'api', 'website', 'onion')),
    url             TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    poll_interval   INTERVAL NOT NULL DEFAULT '6 hours',
    tags            TEXT[] NOT NULL DEFAULT '{}',
    require_tor     BOOLEAN NOT NULL DEFAULT false,
    -- API-specific fields (NULL for rss/website/onion feeds)
    api_method      TEXT,
    api_auth_header TEXT,
    api_data_path   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_polled_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_threat_feeds_enabled ON threat_feeds (enabled);
CREATE INDEX IF NOT EXISTS idx_threat_feeds_updated_at ON threat_feeds (updated_at DESC);

-- Polling history: one row per poll attempt, success or failure. Backs the
-- per-feed status column in the admin feed-management UI.
CREATE TABLE IF NOT EXISTS feed_poll_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_id         UUID NOT NULL REFERENCES threat_feeds(id) ON DELETE CASCADE,
    polled_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    item_count      INTEGER NOT NULL DEFAULT 0,
    alert_count     INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT,
    duration_ms     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_feed_poll_history_feed_id ON feed_poll_history (feed_id, polled_at DESC);

-- --- Audit log: widen allowed actions for the new feed-management endpoints ---
--
-- 0001 and 0002 already constrained + widened this column; each migration
-- widens further rather than assuming a fixed base, so upgrades from any
-- prior version land on the same final constraint. siem.config_updated is
-- NOT included here — that action only exists in the Enterprise build, and
-- is added by 0004_enterprise_rbac_siem.sql instead, so a Community
-- deployment's constraint never mentions an action its binary can't emit.
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_action_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_action_check
    CHECK (action IN (
        'alert.view', 'alert.ack', 'alert.resolve',
        'auth.login', 'auth.login_failed',
        'export.alerts_csv', 'export.audit_csv', 'export.sla_report',
        'feed.created', 'feed.enabled', 'feed.disabled', 'feed.deleted'
    ));

-- Note: sla_targets already exists as of migration 0002_dashboard_metrics.sql
-- (severity PRIMARY KEY, target_minutes) and is reused as-is here — this
-- migration intentionally does NOT redefine it, to avoid a schema conflict.
-- Note: alerts.status and alerts.resolved_at were also added in 0002 and
-- are likewise reused, not redefined, here.
