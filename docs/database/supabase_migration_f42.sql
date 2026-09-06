-- ============================================================
-- ShadowNet Defender — Supabase Migration F4.2: E2E Remediation
--
-- Corrige el drift detectado en E2E real (2026-09-06):
--   - PGRST204: 'analysis_type' no existe en remoto aunque el schema
--     base (supabase_schema.sql) y el DTO (AnalysisType pe/non_pe/
--     realtime/yara) la definen como viva. Se repone idempotentemente.
--   - F4 no aplicada en remoto: faltan evidences/final_verdict/
--     correlation/confidence/degraded/coverage + telemetria de
--     supabase_migration.sql (overlay_analysis, il_behavioral, etc.).
--
-- Ejecutar DESPUES de supabase_schema.sql, supabase_migration.sql,
-- supabase_migration_resend.sql y supabase_migration_f4.sql.
-- Todas las sentencias son idempotentes (IF NOT EXISTS). No DROP,
-- no DELETE, no datos borrados. Compatible con registros existentes.
-- ============================================================

-- ----------------------------------------------------------
-- 1 — analysis_type (viva en DTO/scan_service, ausente en remoto)
-- ----------------------------------------------------------
-- analysis_type distingue pe | non_pe | realtime | yara. YARA hit vs ML
-- es decision de enrutamiento, no legado muerto: se conserva en API y
-- se repone en DB para observabilidad del pipeline.
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS analysis_type TEXT;

-- ----------------------------------------------------------
-- 2 — Telemetria de supabase_migration.sql ausente en remoto
-- ----------------------------------------------------------
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS overlay_analysis JSONB DEFAULT '{}'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS il_behavioral JSONB DEFAULT '{}'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS dotnet_analysis JSONB DEFAULT '{}'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS was_unpacked BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS is_dotnet BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS obfuscator_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS obfuscator_name TEXT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS injection_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS persistence_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS networking_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS credential_theft_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS behavioral_analysis JSONB;

-- ----------------------------------------------------------
-- 3 — F4 Evidence Contract (re-afirmado idempotente)
-- ----------------------------------------------------------
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS evidences JSONB DEFAULT '[]'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS final_verdict JSONB DEFAULT '{}'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS correlation JSONB DEFAULT '{}'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS confidence TEXT DEFAULT 'Low';
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS degraded BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS coverage DOUBLE PRECISION DEFAULT 1.0;

-- ----------------------------------------------------------
-- 4 — Idempotencia + indices (re-afirmado idempotente)
-- ----------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_results_sha_user
    ON scan_results (sha256, user_id) WHERE sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_results_evidences_gin ON scan_results USING GIN (evidences);
CREATE INDEX IF NOT EXISTS idx_scan_results_final_verdict_gin ON scan_results USING GIN (final_verdict);
CREATE INDEX IF NOT EXISTS idx_scan_results_coverage ON scan_results (coverage);
CREATE INDEX IF NOT EXISTS idx_scan_results_analysis_type ON scan_results (analysis_type);

-- ----------------------------------------------------------
-- 5 — RLS re-afirmado (least privilege, sin USING(true))
-- ----------------------------------------------------------
ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "scan_results_all" ON scan_results;
DROP POLICY IF EXISTS "scan_results_select_own" ON scan_results;
DROP POLICY IF EXISTS "scan_results_insert_own" ON scan_results;
DROP POLICY IF EXISTS "scan_results_update_own" ON scan_results;

CREATE POLICY "scan_results_select_own" ON scan_results
    FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "scan_results_insert_own" ON scan_results
    FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "scan_results_update_own" ON scan_results
    FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "users_select_own" ON users;
DROP POLICY IF EXISTS "users_insert_own" ON users;
CREATE POLICY "users_select_own" ON users FOR SELECT USING (auth.uid() = id);
CREATE POLICY "users_insert_own" ON users FOR INSERT WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "incidents_select_own" ON incidents;
CREATE POLICY "incidents_select_own" ON incidents FOR SELECT USING (auth.uid() = user_id);

-- ----------------------------------------------------------
-- 6 — Verification (ejecutar manualmente tras aplicar)
-- ----------------------------------------------------------
-- SELECT column_name, data_type FROM information_schema.columns
--   WHERE table_name='scan_results' ORDER BY ordinal_position;
-- SELECT policyname, cmd, qual, with_check FROM pg_policies
--   WHERE tablename='scan_results';
