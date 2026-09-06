-- ============================================================
-- ShadowNet Defender — Supabase Migration F4: Persistence Hardening
-- Fase 4: Evidence Contract persistence + RLS
--
-- Ejecutar DESPUES de supabase_schema.sql, supabase_migration.sql
-- y supabase_migration_resend.sql
-- Todas las sentencias son idempotentes (IF NOT EXISTS)
-- ============================================================

-- ===========================================================
-- 1 — Columns for F2 Evidence Contract (JSONB)
-- ===========================================================
-- Evidence[] completa, FinalVerdict y Correlation para no perder F1/F2/F3
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS evidences JSONB DEFAULT '[]'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS final_verdict JSONB DEFAULT '{}'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS correlation JSONB DEFAULT '{}'::jsonb;

-- Operational status already exists via earlier migration, but ensure
-- Confidence / degraded / coverage for F2
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS confidence TEXT DEFAULT 'Low';
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS degraded BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS coverage DOUBLE PRECISION DEFAULT 1.0;

-- ===========================================================
-- 2 — Idempotencia: unique index for UPSERT
-- ===========================================================
-- Prefer sha256+user_id+created_at day, but minimal: sha256 + user_id
-- Using unique index to allow ON CONFLICT for idempotency
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_results_sha_user
    ON scan_results (sha256, user_id) WHERE sha256 IS NOT NULL;

-- ===========================================================
-- 3 — RLS: enable and policies (least privilege)
-- ===========================================================
ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;

-- Drop old permissive policies if they exist (to avoid USING(true))
DROP POLICY IF EXISTS "scan_results_all" ON scan_results;
DROP POLICY IF EXISTS "scan_results_select_own" ON scan_results;
DROP POLICY IF EXISTS "scan_results_insert_own" ON scan_results;
DROP POLICY IF EXISTS "scan_results_update_own" ON scan_results;

-- SELECT: user can only read own scans
CREATE POLICY "scan_results_select_own" ON scan_results
    FOR SELECT USING (auth.uid() = user_id);

-- INSERT: user can only insert own scans (WITH CHECK ensures user_id matches auth)
CREATE POLICY "scan_results_insert_own" ON scan_results
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- UPDATE: only own scans, e.g., alert_sent (backend service_role bypasses RLS)
CREATE POLICY "scan_results_update_own" ON scan_results
    FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

-- DELETE: no deletes via anon/authenticated (only service_role)
-- intentionally no DELETE policy for authenticated

-- Users table: users can read own row, insert own row (sync)
DROP POLICY IF EXISTS "users_select_own" ON users;
DROP POLICY IF EXISTS "users_insert_own" ON users;
CREATE POLICY "users_select_own" ON users FOR SELECT USING (auth.uid() = id);
CREATE POLICY "users_insert_own" ON users FOR INSERT WITH CHECK (auth.uid() = id);

-- Incidents: only service_role should insert, authenticated can read own
DROP POLICY IF EXISTS "incidents_select_own" ON incidents;
CREATE POLICY "incidents_select_own" ON incidents FOR SELECT USING (auth.uid() = user_id);

-- ===========================================================
-- 4 — Indices for new columns
-- ===========================================================
CREATE INDEX IF NOT EXISTS idx_scan_results_evidences_gin ON scan_results USING GIN (evidences);
CREATE INDEX IF NOT EXISTS idx_scan_results_final_verdict_gin ON scan_results USING GIN (final_verdict);
CREATE INDEX IF NOT EXISTS idx_scan_results_coverage ON scan_results (coverage);

-- ===========================================================
-- 5 — Verification
-- ===========================================================
-- SELECT column_name, data_type FROM information_schema.columns WHERE table_name='scan_results';
-- SELECT policyname, cmd, qual, with_check FROM pg_policies WHERE tablename='scan_results';
