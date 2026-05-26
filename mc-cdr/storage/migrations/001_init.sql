CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE normalized_events (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ingestion_latency_ms INTEGER,
    provider        TEXT NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp')),
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    principal       JSONB NOT NULL,
    target          JSONB NOT NULL,
    action          TEXT NOT NULL,
    source_ip       INET,
    user_agent      TEXT,
    raw_event       JSONB NOT NULL,
    enrichments     JSONB DEFAULT '{}'
);

SELECT create_hypertable('normalized_events', 'timestamp');
CREATE INDEX ON normalized_events (provider, timestamp DESC);
CREATE INDEX ON normalized_events USING GIN (principal);

CREATE TABLE detections (
    detection_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID REFERENCES normalized_events(event_id),
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rule_id         TEXT NOT NULL,
    technique_id    TEXT NOT NULL,
    tactic          TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      FLOAT NOT NULL,
    details         JSONB,
    status          TEXT DEFAULT 'open'
);

CREATE TABLE response_actions (
    action_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id    UUID REFERENCES detections(detection_id),
    action_type     TEXT NOT NULL,
    provider        TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    initiated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    status          TEXT NOT NULL,
    result          JSONB,
    latency_ms      INTEGER
);
