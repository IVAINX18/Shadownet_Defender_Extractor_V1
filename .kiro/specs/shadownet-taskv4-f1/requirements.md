# Requirements Document

## Introduction

Este documento cubre la fase F1 — Estabilización de ShadowNet Defender (TaskV4), compuesta por cuatro tareas prioritarias (T-01 a T-04) que deben completarse antes de que el sistema sea desplegable en producción. Las tareas corrigen comportamientos críticos: alertas silenciosas en n8n ante amenazas DANGEROUS con label BENIGN, respuestas HTTP 500 ante JWT expirados, la presencia del estado `operational_status=UNKNOWN` en el pipeline, y la ausencia de timeout configurable en el extractor de features.

ShadowNet Defender es un sistema híbrido multicapa de detección de malware con Python 3.11, FastAPI, ONNX Runtime, YARA y Ollama. El contrato de 2381 dimensiones del extractor es invariante — los artefactos `scaler.pkl` y `best_model.onnx` no se modifican en esta fase.

---

## Glossary

- **N8N_Client**: Módulo `core/integrations/n8n_client.py` que envía webhooks a n8n ante detecciones críticas.
- **Auth_Dependency**: Módulo `backend/app/api/dependencies/auth.py` que valida JWTs de Supabase en cada request protegido.
- **Engine**: Motor central `core/engine.py` que orquesta el pipeline híbrido de detección (YARA → UPX → ML → Overlay → .NET → IL → Behavioral).
- **Extractor**: Clase `PEFeatureExtractor` en `extractors/extractor.py` que produce el vector de 2381 dimensiones a partir de un archivo PE.
- **operational_status**: Campo del resultado de escaneo que indica el estado operacional del archivo analizado. Valores válidos: `CLEAN`, `SUSPICIOUS`, `DANGEROUS`.
- **label**: Campo del resultado de escaneo producido por el modelo ONNX. Valores: `MALWARE`, `BENIGN`, `NOT_PE`, `UNKNOWN`.
- **DANGEROUS**: Valor de `operational_status` que indica que el archivo presenta indicadores de amenaza crítica, independientemente del `label` asignado por el modelo ML.
- **SUSPICIOUS**: Valor de `operational_status` que indica riesgo moderado o degradación del análisis.
- **CLEAN**: Valor de `operational_status` que indica ausencia de indicadores de riesgo detectados.
- **UNKNOWN**: Valor de `operational_status` prohibido tras T-03. Nunca debe aparecer en un resultado de escaneo finalizado.
- **fail-secure**: Principio de seguridad por defecto ante configuración ausente — retornar 401 en lugar de 500.
- **Hypothesis**: Librería de property-based testing usada en `tests/properties/`.
- **EXTRACTOR_TIMEOUT_SECONDS**: Variable de entorno configurable (default 15s) que limita el tiempo máximo de `extract_features()`.
- **degradation_reason**: Campo en el resultado que explica por qué el pipeline operó en modo degradado.
- **N8N_ALERT_ON_STATUS**: Variable de entorno (default `DANGEROUS,SUSPICIOUS`) que define los valores de `operational_status` que disparan alertas n8n.
- **N8N_ALERT_ON_LABEL_ONLY**: Variable de entorno booleana (default `false`). Si es `true`, solo se alerta por `label == malicious`.

---

## Requirements

### Requirement 1: Alertas n8n por operational_status crítico (T-01)

**User Story:** Como analista SOC, quiero que n8n reciba alertas cuando un archivo tiene `operational_status=DANGEROUS` aunque el modelo ML lo clasifique como `label=BENIGN`, para que el hallazgo multicapa sea accionable en tiempo real.

#### Acceptance Criteria

1. WHEN `send_scan_result` is called with `operational_status=DANGEROUS`, THE N8N_Client SHALL send a webhook alert regardless of the value of `label`.
2. WHEN `send_scan_result` is called with `operational_status=SUSPICIOUS`, THE N8N_Client SHALL send a webhook alert when `SUSPICIOUS` is included in `N8N_ALERT_ON_STATUS`.
3. WHEN `N8N_ALERT_ON_LABEL_ONLY=true`, THE N8N_Client SHALL only send alerts when `label == "malicious"`, ignoring `operational_status`.
4. WHEN `N8N_ALERT_ON_STATUS` is set, THE N8N_Client SHALL parse the comma-separated list and alert on each listed status value.
5. WHILE `N8N_ENABLED=false`, THE N8N_Client SHALL not send any webhook regardless of `operational_status` or `label`.
6. WHEN `operational_status=CLEAN` and `label != "malicious"`, THE N8N_Client SHALL skip the alert without raising an exception.
7. WHEN `label == "malicious"` and `operational_status == "DANGEROUS"`, THE N8N_Client SHALL set `event_type = "malware_critical"` in the webhook payload.
8. WHEN `operational_status == "DANGEROUS"` and `label != "malicious"`, THE N8N_Client SHALL set `event_type = "dangerous_detected"` in the webhook payload.
9. THE N8N_Client SHALL never raise an exception to its caller regardless of network errors or configuration issues.
10. FOR ALL inputs where `operational_status not in N8N_ALERT_ON_STATUS` and `label != "malicious"`, THE N8N_Client SHALL return `False` (round-trip: non-critical → no alert).

### Requirement 2: Respuesta HTTP 401 ante JWT expirado o ausente (T-02)

**User Story:** Como desarrollador de seguridad, quiero que cualquier JWT expirado, inválido o emitido con configuración Supabase ausente retorne HTTP 401, para que el sistema opere en modo fail-secure y nunca exponga un HTTP 500 en el path de autenticación.

#### Acceptance Criteria

1. WHEN a request carries an expired JWT, THE Auth_Dependency SHALL return `HTTPException(status_code=401)` with detail `"token expired"` or `"token invalid"`.
2. WHEN a request carries a malformed or invalid JWT, THE Auth_Dependency SHALL return `HTTPException(status_code=401)` and SHALL NOT propagate `InvalidTokenError` as an unhandled exception.
3. IF `SUPABASE_URL` and `SUPABASE_JWT_SECRET` are both absent or empty, THEN THE Auth_Dependency SHALL return `HTTPException(status_code=401)` with a generic error message, applying the fail-secure principle.
4. THE Auth_Dependency SHALL NOT log JWT secret values or token payloads in any log output.
5. WHEN the JWKS client raises any exception during key resolution, THE Auth_Dependency SHALL fall back to HS256 decoding or return `HTTPException(status_code=401)` if no fallback is available.
6. IF an unexpected exception occurs in the token decoding path, THEN THE Auth_Dependency SHALL catch it and return `HTTPException(status_code=401)`, never HTTP 500.
7. THE Auth_Dependency SHALL preserve the existing behavior for valid tokens — returning `{"id": "<uuid>", "email": "<email>"}`.

### Requirement 3: Eliminación del estado operational_status=UNKNOWN (T-03)

**User Story:** Como ingeniero del sistema, quiero que `operational_status` solo tome los valores `CLEAN`, `SUSPICIOUS` o `DANGEROUS` en cualquier resultado de escaneo, para garantizar la invariancia del contrato de datos y eliminar estados ambiguos en la telemetría.

#### Acceptance Criteria

1. THE Engine SHALL produce `operational_status` values exclusively from the set `{CLEAN, SUSPICIOUS, DANGEROUS}` for any completed scan result.
2. WHEN the YARA phase detects a match and the Risk Engine has not yet run, THE Engine SHALL set `operational_status = "DANGEROUS"` in the YARA early-exit result.
3. WHEN the ML phase fails with an ONNX exception, THE Engine SHALL set `operational_status = "SUSPICIOUS"` rather than `"UNKNOWN"`.
4. WHEN the watchdog timeout expires before scan completion, THE Engine SHALL set `operational_status = "SUSPICIOUS"` in the timeout fallback result.
5. IF `operational_status` is set to `"UNKNOWN"` at any intermediate point in the pipeline, THEN THE Engine SHALL replace it with `"SUSPICIOUS"` before returning the final result.
6. THE `ScanResult` DTO SHALL NOT include `"UNKNOWN"` as a valid or default value for `operational_status`.
7. WHEN a scan of `procexp64.exe` completes (YARA hit + risk engine without triggers), THE Engine SHALL produce `operational_status = "DANGEROUS"`, not `"UNKNOWN"`.
8. THE Engine SHALL maintain the invariant `operational_status ∈ {CLEAN, SUSPICIOUS, DANGEROUS}` across all pipeline phases including YARA early-exit, ML failure, timeout, non-PE, and overlay phases.

### Requirement 4: Timeout configurable para el extractor de features (T-04)

**User Story:** Como operador del sistema, quiero que la extracción de features PE tenga un timeout configurable por variable de entorno, para que archivos complejos o malformados no bloqueen el pipeline indefinidamente y el sistema pueda continuar con una respuesta degradada.

#### Acceptance Criteria

1. THE Engine SHALL wrap the `extract_features()` call in a `concurrent.futures.ThreadPoolExecutor` with a timeout controlled by `EXTRACTOR_TIMEOUT_SECONDS`.
2. WHEN `EXTRACTOR_TIMEOUT_SECONDS` is set as an environment variable, THE Engine SHALL read and apply it as the extraction timeout limit.
3. IF the `extract_features()` call exceeds `EXTRACTOR_TIMEOUT_SECONDS`, THEN THE Engine SHALL set `operational_status = "SUSPICIOUS"` and `degradation_reason = "extractor_timeout"` and continue the pipeline.
4. WHEN the extractor times out, THE Engine SHALL NOT raise an exception to the caller; it SHALL continue subsequent pipeline phases with the degraded result.
5. THE `EXTRACTOR_TIMEOUT_SECONDS` configuration SHALL have a default value of 15 seconds when the environment variable is not set.
6. WHERE `EXTRACTOR_TIMEOUT_SECONDS` is present in `configs/settings.py` and `backend/app/config.py`, THE Engine SHALL read from a single authoritative source without duplication.
7. WHEN the extractor times out, THE Engine SHALL log the timeout event including the file name and configured timeout value.
8. THE Engine SHALL preserve the existing `ANALYSIS_TIMEOUT_SECONDS` watchdog — the extractor timeout (T-04) operates as an inner timeout within the outer pipeline watchdog.
9. WHEN a file with many PE sections triggers extractor timeout, THE Engine SHALL produce a valid `ScanResult` with `operational_status = "SUSPICIOUS"` and `label` set to a non-null value.

---

## Test Requirements

### Requirement 5: Cobertura de tests para F1

**User Story:** Como desarrollador, quiero que cada tarea de F1 tenga cobertura de test explícita, para garantizar que `pytest tests/ -v` alcance ≥ 155/158 sin nuevos FAILED.

#### Acceptance Criteria

1. THE test suite SHALL include `test_send_scan_result_skips_benign` updated to verify that a `result=benign` + `operational_status=DANGEROUS` scan DOES trigger an alert.
2. THE test suite SHALL include a new test `test_send_scan_result_sends_dangerous_benign_label` that verifies `operational_status=DANGEROUS` + `label=BENIGN` produces a webhook call.
3. THE test suite SHALL replace `test_prop16_non_alert_always_skip` with a property `non_critical_always_skip` that uses `N8N_ALERT_ON_STATUS` to define the skip condition.
4. THE test suite SHALL include `TestExpiredJWT::test_expired_token_rejected` passing with HTTP 401.
5. THE test suite SHALL include `test_yara_match_never_unknown` verifying that YARA early-exit never sets `operational_status = "UNKNOWN"`.
6. THE test suite SHALL include `test_extractor_timeout_fallback` verifying that a simulated extractor timeout produces `operational_status = "SUSPICIOUS"` and `degradation_reason = "extractor_timeout"`.
7. WHEN all F1 tests pass, THE test suite SHALL report ≥ 155 passed out of 158 total with 0 new FAILED regressions.
