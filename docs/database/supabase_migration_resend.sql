-- ============================================================
-- ShadowNet Defender — Supabase Migration: Resend Alert Webhook
-- Fase 1: n8n → Supabase Database Webhook + Edge Function
--
-- Objetivo: preparar scan_results para alertas via Resend sin
-- romper flujo actual n8n. 100% idempotente y reversible.
-- No crea triggers SQL (webhook se configura en Dashboard).
--
-- Ejecutar DESPUES de supabase_schema.sql y
-- supabase_migration.sql. Usar IF NOT EXISTS para ser
-- seguro en re-ejecuciones.
-- ============================================================

-- ===========================================================
-- 1 — Columna de idempotencia para alertas (previene duplicados)
-- ===========================================================
-- alert_sent evita enviar el mismo email dos veces si el webhook
-- se reintenta o si el scan se re-inserta por retry offline.
ALTER TABLE scan_results
    ADD COLUMN IF NOT EXISTS alert_sent BOOLEAN DEFAULT FALSE;

-- Comentario para documentacion en catalogo
COMMENT ON COLUMN scan_results.alert_sent IS
    'Idempotencia: TRUE si Edge Function send-malware-alert ya envio email via Resend. Evita duplicados en retries.';

-- ===========================================================
-- 2 — Compatibilidad: asegurar columnas que la Edge Function lee
-- ===========================================================
-- Las siguientes columnas ya existen via supabase_migration.sql
-- pero se verifican aqui para entornos que solo aplicaron
-- supabase_schema.sql. No se duplican si ya existen.
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS operational_status TEXT DEFAULT 'UNKNOWN';
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS sha256 TEXT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS yara_matches JSONB DEFAULT '[]'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS detection_phases JSONB DEFAULT '[]'::jsonb;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS user_email TEXT;
-- Nota: user_id, file_name, result, risk_level, score ya existen en schema base.

-- ===========================================================
-- 3 — Indices para filtrado de webhook y audits
-- ===========================================================
CREATE INDEX IF NOT EXISTS idx_scan_results_alert_sent
    ON scan_results (alert_sent) WHERE alert_sent = FALSE;

CREATE INDEX IF NOT EXISTS idx_scan_results_result_opstatus
    ON scan_results (result, operational_status);

-- Reusa indices ya existentes si ya fueron creados:
-- idx_scan_results_sha256, idx_scan_results_op_status, idx_scan_results_alert_sent

-- ===========================================================
-- 4 — Verificacion (ejecutar para confirmar migracion)
-- ===========================================================
-- SELECT column_name, data_type, column_default
-- FROM information_schema.columns
-- WHERE table_name = 'scan_results' AND column_name = 'alert_sent';
--
-- SELECT indexname FROM pg_indexes WHERE tablename = 'scan_results';

-- ===========================================================
-- 5 — Configuracion del Database Webhook (NO SQL, Dashboard)
-- ===========================================================
-- El webhook que dispara la Edge Function NO se crea via SQL.
-- Debe configurarse en Supabase Dashboard:
--
--   Dashboard → Database → Webhooks → Create Webhook
--     Table: scan_results
--     Events: INSERT
--     Type: HTTP Request
--     URL: https://<PROJECT_ID>.supabase.co/functions/v1/send-malware-alert
--     HTTP Method: POST
--     Headers: Content-Type: application/json
--              Authorization: Bearer <SUPABASE_ANON_KEY>
--     Condition (opcional, recomendado):
--       (NEW.result = 'malicious' OR NEW.operational_status = 'DANGEROUS')
--       AND COALESCE(NEW.alert_sent, FALSE) = FALSE
--
-- Alternativa via SQL (Supabase pg_net, si esta habilitado):
--   SELECT net.http_post(
--     url := 'https://<PROJECT_ID>.supabase.co/functions/v1/send-malware-alert',
--     headers := '{"Content-Type":"application/json","Authorization":"Bearer <ANON_KEY>"}'::jsonb,
--     body := to_jsonb(NEW)
--   );
-- Pero se recomienda Dashboard para simplicidad y observabilidad.
--
-- Ver Fase 2: supabase/functions/send-malware-alert/index.ts
-- ===========================================================

-- ===========================================================
-- 6 — Rollback (reversible, ejecutar solo si se revierte Fase 1)
-- ===========================================================
-- -- Quitar columna (solo si no hay datos criticos dependientes):
-- -- ALTER TABLE scan_results DROP COLUMN IF EXISTS alert_sent;
-- -- DROP INDEX IF EXISTS idx_scan_results_alert_sent;
-- -- DROP INDEX IF EXISTS idx_scan_results_result_opstatus;
-- -- El webhook del Dashboard debe eliminarse manualmente:
-- -- Dashboard → Database → Webhooks → Delete
-- ===========================================================
