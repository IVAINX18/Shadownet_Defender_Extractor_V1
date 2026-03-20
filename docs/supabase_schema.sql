-- ============================================================
-- ShadowNet Defender — Supabase Schema
-- ============================================================

-- Users table — synced from Supabase Auth
CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scan results table
CREATE TABLE IF NOT EXISTS scan_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_id         UUID REFERENCES users(id),
    user_email      TEXT,
    file_name       TEXT NOT NULL,
    scan_type       TEXT NOT NULL DEFAULT 'single',
    result          TEXT NOT NULL,
    risk_level      TEXT NOT NULL DEFAULT 'low',
    score           DOUBLE PRECISION DEFAULT 0.0,
    explanation     TEXT,
    scan_duration   DOUBLE PRECISION,
    offline         BOOLEAN DEFAULT FALSE,
    metadata        JSONB DEFAULT '{}'::jsonb
);

-- Indices
CREATE INDEX IF NOT EXISTS idx_scan_results_result ON scan_results (result);
CREATE INDEX IF NOT EXISTS idx_scan_results_risk   ON scan_results (risk_level);
CREATE INDEX IF NOT EXISTS idx_scan_results_user   ON scan_results (user_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_date   ON scan_results (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_email         ON users (email);
