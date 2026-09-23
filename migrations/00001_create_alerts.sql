-- +goose Up
CREATE TABLE IF NOT EXISTS sentinel_alerts (
    id                text PRIMARY KEY,
    rule_id           text NOT NULL,
    rule_key          text NOT NULL,
    title             text NOT NULL,
    severity          text NOT NULL,
    status            text NOT NULL,
    confidence        double precision NOT NULL DEFAULT 0,
    mitre             text[] NOT NULL DEFAULT '{}',
    description       text NOT NULL DEFAULT '',
    asset             text NOT NULL DEFAULT '',
    src_ip            text NOT NULL DEFAULT '',
    geo               jsonb,
    count             integer NOT NULL DEFAULT 0,
    blocked_count     integer NOT NULL DEFAULT 0,
    unique_paths      integer NOT NULL DEFAULT 0,
    distinct_assets   integer NOT NULL DEFAULT 0,
    event_ids         text[] NOT NULL DEFAULT '{}',
    started_at        timestamptz NOT NULL,
    last_seen_at      timestamptz NOT NULL,
    assignee          text NOT NULL DEFAULT '',
    assigned_at       timestamptz,
    status_changed_at timestamptz,
    responded_at      timestamptz,
    resolved_at       timestamptz,
    resolution        text NOT NULL DEFAULT '',
    actions           jsonb NOT NULL DEFAULT '[]',
    extra             jsonb,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON sentinel_alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON sentinel_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_asset ON sentinel_alerts (asset);
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON sentinel_alerts (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_key ON sentinel_alerts (rule_id, rule_key);

-- +goose Down
DROP TABLE IF EXISTS sentinel_alerts;
