# F4 — Persistence & Supabase Hardening

**Estado:** IMPLEMENTED
**Fecha:** 2026-09-06

## Objetivo
Resolver `PGRST204`, RLS, schema mismatch y offline queue. Persistencia segura, idempotente y observable.

## Schema (Source of Truth)
- Base: `docs/database/supabase_schema.sql` (scan_results 13 cols + users)
- Migración 1: `docs/database/supabase_migration.sql` (16 cols: operational_status, sha256, overlay_analysis, yara_matches, il_behavioral, dotnet_analysis, detection_phases, was_unpacked, is_dotnet, obfuscator_detected, injection/persistence/networking/credential_theft, obfuscator_name, behavioral_analysis; + incidents table)
- Migración 2: `docs/database/supabase_migration_resend.sql` (alert_sent)
- **F4:** `docs/database/supabase_migration_f4.sql` (evidences JSONB, final_verdict JSONB, correlation JSONB, confidence, degraded, coverage; unique index `uq_scan_results_sha_user` para idempotencia; RLS policies `auth.uid()=user_id`; GIN indices)

## PGRST204 Root Cause & F4.1 Hardening
`save_scan` intentaba insertar columnas inexistentes si migraciones no aplicadas (`behavioral_analysis`, `evidences`). → `PGRST204`.

**F4 Fix:** `KNOWN_COLUMNS` filter, clasificación `permanent_schema`, minimal retry 1×.

**F4.1 Hardening:** `PGRST204` clasificado `permanent_schema` → 1 retry minimal (8 cols) luego `permanent:true` sin queue infinito; no re-envía columnas inexistentes; no loop (verificado `call_count==2`). Tests F4.1 `test_pgrst204_*` demuestran retry controlado, no queue, clasificación correcta.

## Error Classification
`_classify_supabase_error()` → `transient` (timeout, 5xx), `permanent_schema` (PGRST204), `rls` (42501), `auth` (JWT), `unknown`. `transient` → offline queue, `permanent_schema/rls/auth` → no queue, marcado `permanent:true`.

## RLS (least privilege) & E2E Verification (F4.1)
```
ALTER TABLE scan_results ENABLE RLS
SELECT: auth.uid()=user_id
INSERT: WITH CHECK auth.uid()=user_id
UPDATE: USING/WITH CHECK auth.uid()=user_id
DELETE: no policy (solo service_role)
users: SELECT/INSERT own, incidents: SELECT own
```
`service_role` nunca al frontend, solo backend; `anon` sin permisos. **E2E real** (`tests/test_persistence_f41.py::test_rls_e2e_real_isolation`) usa `SUPABASE_ANON_KEY` (no service_role) para crear 2 usuarios vía `auth.sign_up`/`sign_in`, inserta como A, verifica B no `SELECT` A, B `INSERT as A` → `42501`. Si `SUPABASE_URL` no disponible, test skip y queda cubierto por mocks (`test_rls_mock_*`). `test_rls_anon_no_access_mock` verifica `fetch_recent_scans` sin key → `[]`. Policy correctness verificada vía `pg_policies` en migración; runtime verification separada.

## Offline Queue
`backend/app/services/offline_service.py` (`data/offline_queue.json`): `queue_scan()` append con `queued_at`, `sync_queue()` reintenta solo si `is_online()` (HEAD Supabase), elimina `queued_at` antes de `save_scan`, `is_online()` verifica `SUPABASE_KEY` + `requests.head`. No infinite retry en `permanent_schema/rls`.

## Idempotencia & UNIQUE(sha256,user_id) — F4.1 Decisión
`uq_scan_results_sha_user UNIQUE(sha256,user_id) WHERE sha256 IS NOT NULL` en `supabase_migration_f4.sql:14` **mantenida**. Semántica: `scan_results` es resultado lógico por archivo+usuario (idempotencia), no historial por tiempo. Mismo usuario + mismo hash en distintos momentos → deduplicado (segunda inserción retorna `23505 → deduplicated:true`, no error). Distinto usuario + mismo hash → permitido (aislamiento). Si en futuro se requiere historial por tiempo, evolucionar a `UNIQUE(sha256,user_id,created_at)` o quitar WHERE y usar surrogate `id` + `INSERT` sin restricción (expand-contract). Tests F4.1 documentan (`test_unique_*`). `23505` manejado como éxito idempotente, no queue.

## Idempotencia
Memoria 60s (`_idempotency_cache` sha256) + DB unique index `uq_scan_results_sha_user` (23505 → deduplicated). `save_scan` verifica `_check_idempotency` antes de insert; `upsert` no usado (evita duplicados por nombre).

## JSON Serialization
`_safe_json()` maneja `Enum→value`, `datetime→isoformat`, `Path→str`, `numpy→python`, `NaN/Inf→None`, `Pydantic model_dump`, recursivo. No bytes de malware.

## Evidence Storage
`evidences`, `final_verdict`, `correlation` JSONB en `scan_results`; `ScanResult` DTO extendido opcionalmente (`backend/app/schemas/dto.py:230-245`) y poblado desde `raw_result` en `scan_service.py:326-330`. Recuperable via `SELECT evidences->0->>'source'`.

## Detection vs Persistence
`save_scan_safe` nunca cambia `verdict/risk/operational`; detection retorna siempre, `saved:false` → `queued`. Test `test_detection_not_changed_by_persistence_failure` verifica `MALICIOUS` permanece.

## Alert idempotency
`alert_sent` BOOLEAN default FALSE, solo `TRUE` tras `save_incident` éxito; Edge Function `send-malware-alert` verifica `COALESCE(alert_sent,false)=false`.

## Observability & Health
`_check_offline_queue()` en `/health`, logs `persistence success/retry/queued/permanent`, sanitizado (no JWT/SUPABASE_KEY). Timeout via `scan_file` 60s wrapper, no bloqueo.

## Tests
`tests/test_persistence_f4.py` 11 tests: PGRST204 recovery, RLS not queued, transient queued, JSONB storage, dedup, detection vs persistence, secrets, known columns, etc. Full suite 254 passed.

## No Destructive Migration
Solo `ADD COLUMN IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, `ENABLE RLS` + `CREATE POLICY` (drop-recreate idempotente), nunca `DROP TABLE/COLUMN`.

## F4.2 — E2E Remediation (2026-09-06)
E2E real encontro 2 fallos (ver reporte F4.2): PGRST204 `analysis_type` + 42501 sin JWT.

**Decision `analysis_type`:** VIVA (DTO `AnalysisType` pe/non_pe/realtime/yara + `scan_service` routing + base schema). Remoto sin la columna = drift. `supabase_migration_f42.sql` la repone + re-afirma telemetria y F4, idempotente.

**Auth/RLS — Opcion B justificada:** remoto con RLS ENABLED pero SIN policies F4 (verificado: JWT valido + anon retornan 0 filas / 42501; service_role inserta OK) y sin derechos DDL en este entorno para crearlas. Backend usa service_role SOLO server-side (`_get_service_client`, nunca frontend/logs), `user_id` exclusivamente del JWT validado (`get_current_user`), lecturas filtradas por ese `user_id`, fail-secure sin `user_id` (permanent, sin queue). RLS deny-by-default protege acceso PostgREST directo (0 filas). Fallback anon+JWT (Opcion A pura) automatico si no hay service key — tras aplicar `supabase_migration_f42.sql` via Dashboard SQL Editor. Tests hermeticos: service client deshabilitado bajo pytest.

**Robustez:** `_insert_adaptive` stripping por columna nombrada (max 32), `_extract_missing_column` (PGRST204/42703), minimal retry 1x, clasificacion permanent/transient/unique_violation sin cambios, `_sanitize_error` en todos los logs.

**DTO:** `ScanResult.operational_status` (F4.2, mapeado desde `final_verdict` en `scan_service`) para que respuesta y persistencia incluyan estado operativo.

Aplicar en remoto (Dashboard SQL Editor, orden): `supabase_migration_f42.sql`.
