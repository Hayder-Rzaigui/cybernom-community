-- CyberNom migration 0002: alert status, SLA tracking, source categorization
--
-- Backs the dashboard's status donut, SLA compliance donut, and
-- "log collection by source" chart with real data instead of the static
-- mockup numbers they replace. Apply after 0001_init.sql.

-- Migration 0002 adds a new audit action, 'alert.resolve', emitted by
-- handleResolveAlert (see internal/api/handlers_alerts.go). The original
-- CHECK constraint from 0001 didn't include it, so it must be widened here
-- rather than left to fail silently on the first resolve action.
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_action_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_action_check
    CHECK (action IN ('alert.view', 'alert.ack', 'alert.resolve', 'auth.login', 'auth.login_failed'));

-- Alert status: a superset of the old boolean `acknowledged` column.
--   new        — untouched since creation (equivalent to acknowledged = false)
--   in_triage  — an analyst has acknowledged it but not yet resolved it
--   resolved   — an analyst has explicitly marked it resolved
--
-- `acknowledged` is kept and kept in sync via trigger below rather than
-- dropped outright: existing code (audit log action names, any external
-- integration someone may have built against the old column) keeps working
-- unmodified. New code should read/write `status`; `acknowledged` becomes a
-- derived convenience column (true iff status <> 'new').
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'in_triage', 'resolved')),
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

-- Backfill status from the existing acknowledged column so upgrading
-- doesn't silently reclassify every previously-acknowledged alert as "new".
UPDATE alerts SET status = 'in_triage' WHERE acknowledged = true AND status = 'new';

-- Keep `acknowledged` truthful for any code (or operator running ad-hoc
-- queries) that still reads it directly, without requiring every write
-- path to remember to set both columns.
CREATE OR REPLACE FUNCTION sync_alert_acknowledged() RETURNS TRIGGER AS $$
BEGIN
    NEW.acknowledged := (NEW.status <> 'new');
    IF NEW.status = 'resolved' AND NEW.resolved_at IS NULL THEN
        NEW.resolved_at := now();
    ELSIF NEW.status <> 'resolved' THEN
        NEW.resolved_at := NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sync_alert_acknowledged ON alerts;
CREATE TRIGGER trg_sync_alert_acknowledged
    BEFORE INSERT OR UPDATE OF status ON alerts
    FOR EACH ROW EXECUTE FUNCTION sync_alert_acknowledged();

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);

-- SLA targets per severity. A row-per-severity config table rather than a
-- hardcoded constant in Go so operators can tune targets (e.g. a stricter
-- critical SLA for a regulated environment) without a code change/redeploy.
CREATE TABLE IF NOT EXISTS sla_targets (
    severity          TEXT PRIMARY KEY CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    target_minutes    INTEGER NOT NULL CHECK (target_minutes > 0)
);

INSERT INTO sla_targets (severity, target_minutes) VALUES
    ('critical', 4 * 60),
    ('high',     24 * 60),
    ('medium',   72 * 60),
    ('low',      7 * 24 * 60)
ON CONFLICT (severity) DO NOTHING;

-- Source category mapping for the "log collection by source" chart. The
-- mockup groups arbitrary source_feed values (BreachForums, Telegram —
-- leaks-daily, GitHub gist watch, ...) into 4 buckets: Forums, Pastes,
-- Telegram, Code hosts. source_feed is free text set by the ingester
-- config, so this table maps known feed names to a bucket rather than
-- trying to infer it from the string at query time. Unmapped feeds fall
-- back to "Other" in the query (see storage.SourceVolumeBySource), so
-- adding a new feed to config.yaml without also adding a row here degrades
-- gracefully instead of breaking the chart.
CREATE TABLE IF NOT EXISTS source_categories (
    source_feed TEXT PRIMARY KEY,
    category    TEXT NOT NULL CHECK (category IN ('Forums', 'Pastes', 'Telegram', 'Code hosts', 'Other'))
);

INSERT INTO source_categories (source_feed, category) VALUES
    ('BreachForums',        'Forums'),
    ('XSS.is',              'Forums'),
    ('XSS.is monitor',      'Forums'),
    ('RaidForums',          'Forums'),
    ('Pastebin scraper',    'Pastes'),
    ('Ghostbin scraper',    'Pastes'),
    ('Telegram — leaks',        'Telegram'),
    ('Telegram — leaks-daily',  'Telegram'),
    ('GitHub gist watch',   'Code hosts'),
    ('GitLab snippet watch','Code hosts')
ON CONFLICT (source_feed) DO NOTHING;
