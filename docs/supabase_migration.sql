-- ============================================================
-- ShadowNet Defender — Supabase Migration Script
-- Auditoría: Telemetría completa + tabla incidents
--
-- Ejecutar DESPUÉS del schema base (docs/supabase_schema.sql).
-- Todas las sentencias usan IF NOT EXISTS para ser idempotentes.
-- ============================================================


-- ===========================================================
-- 11.1 — ALTER TABLE scan_results: 16 columnas nuevas
-- ===========================================================

-- Operational status: CLEAN | SUSPICIOUS | DANGEROUS | UNKNOWN
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS operational_status TEXT DEFAULT 'UNKNOWN';

-- SHA-256 del archivo escaneado
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS sha256 TEXT;

-- Campos JSONB de telemetría extendida
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS overlay_analysis JSONB DEFAULT '{}'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS yara_matches JSONB DEFAULT '[]'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS il_behavioral JSONB DEFAULT '{}'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS dotnet_analysis JSONB DEFAULT '{}'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS detection_phases JSONB DEFAULT '[]'::jsonb;

-- Flags booleanos
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS was_unpacked BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS is_dotnet BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS obfuscator_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS injection_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS persistence_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS networking_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS credential_theft_detected BOOLEAN DEFAULT FALSE;

-- Nombre del ofuscador detectado (si aplica)
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS obfuscator_name TEXT;

-- BehavioralShield report (Fase 7)
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS behavioral_analysis JSONB;


-- ===========================================================
-- 11.2 — CREATE TABLE incidents
-- ===========================================================

CREATE TABLE IF NOT EXISTS incidents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    scan_id             UUID REFERENCES scan_results(id),
    user_id             UUID REFERENCES users(id),
    file_name           TEXT NOT NULL,
    severity            TEXT NOT NULL DEFAULT 'critical',
    operational_status  TEXT NOT NULL DEFAULT 'DANGEROUS',
    timestamp           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Índices para incidents
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created  ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_scan_id  ON incidents (scan_id);
CREATE INDEX IF NOT EXISTS idx_incidents_user_id  ON incidents (user_id);


-- ===========================================================
-- 11.3 — Índices en scan_results para consultas frecuentes
-- ===========================================================

-- Índice en sha256 para verificación de idempotencia y búsquedas
CREATE INDEX IF NOT EXISTS idx_scan_results_sha256 ON scan_results (sha256);

-- Índice en operational_status para filtrado de amenazas
CREATE INDEX IF NOT EXISTS idx_scan_results_op_status ON scan_results (operational_status);

-- Índice compuesto para consultas de idempotencia (sha256 + created_at)
CREATE INDEX IF NOT EXISTS idx_scan_results_sha256_date ON scan_results (sha256, created_at DESC);
