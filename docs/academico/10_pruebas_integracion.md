# Pruebas de Integración — Documentación

> Suite ejecutada: `python -m pytest tests/ -v` en 2026-08-18.
> Incluye integration/, properties/, security/.

---

## `tests/integration/test_pipeline_e2e.py`

**Objetivo**: Verificar el pipeline end-to-end sobre datos reales.

| Test | Estado | Qué verifica |
|------|--------|--------------|
| `TestPipelineAccuracy::test_accuracy_above_threshold` | ⏭️ SKIPPED | Accuracy del modelo ≥ 90% sobre test set |
| `TestPipelineAccuracy::test_test_set_dimensions` | ✅ PASSED | X_test tiene shape (1000, 2381) |
| `TestPipelineAccuracy::test_labels_binary` | ✅ PASSED | y_test contiene solo 0 y 1 |

**Razón del skip de `test_accuracy_above_threshold`**: El test verifica que el modelo produzca accuracy ≥ 90% sobre `data/test_set/`. Como se documentó en `07_metricas_y_resultados.md`, el test set es sintético e incompatible con el scaler de producción. La accuracy real con el pipeline completo es 50% (equivalente a aleatorio), por lo que el test es omitido por diseño.

---

## `tests/integration/test_supabase_client.py`

**Objetivo**: Verificar integración con Supabase para persistencia de resultados.

| Test | Estado | Qué verifica |
|------|--------|--------------|
| `TestSupabaseTelemetryFields::test_record_has_all_telemetry_fields` | ✅ PASSED | El registro incluye todos los campos de telemetría |
| `TestSupabaseTelemetryFields::test_safe_json_applied` | ✅ PASSED | `safe_json()` aplicado antes de enviar a Supabase |
| `TestSaveIncidentOnDangerous::test_incident_saved_on_dangerous` | ✅ PASSED | Incidente guardado cuando `operational_status == "DANGEROUS"` |
| `TestSaveIncidentOnDangerous::test_no_incident_on_clean` | ✅ PASSED | No se crea incidente cuando `operational_status == "CLEAN"` |
| `TestOfflineFallback::test_fallback_offline_on_supabase_failure` | ✅ PASSED | Si Supabase falla, datos van a cola offline (JSON en disco) |
| `TestOfflineFallback::test_fallback_does_not_propagate` | ✅ PASSED | El fallo de Supabase no se propaga como excepción al pipeline |
| `TestIdempotency::test_same_sha256_within_60s_deduplicated` | ✅ PASSED | Mismo SHA-256 en <60s no crea registro duplicado |

**Cobertura verificada**: persistencia de incidentes, deduplicación, fallback offline, safe serialization.

---

## `tests/security/test_backend_security.py`

**Objetivo**: Verificar protecciones de seguridad en el backend FastAPI.

| Test | Estado | Qué verifica |
|------|--------|--------------|
| `TestNoJWT::test_scan_file_no_auth` | ✅ PASSED | Sin JWT → 401 Unauthorized |
| `TestNoJWT::test_scan_multiple_no_auth` | ✅ PASSED | Batch scan sin JWT → 401 |
| `TestExpiredJWT::test_expired_token_rejected` | ❌ FAILED | JWT expirado → debería ser 401, retorna 500 |
| `TestDoubleExtension::test_double_extension_rejected[*.pdf.exe]` | ✅ PASSED | Extensión doble `.pdf.exe` rechazada |
| `TestDoubleExtension::test_double_extension_rejected[*.jpg.dll]` | ✅ PASSED | Extensión doble `.jpg.dll` rechazada |
| `TestDoubleExtension::test_double_extension_rejected[*.docx.bat]` | ✅ PASSED | Extensión doble `.docx.bat` rechazada |
| `TestDoubleExtension::test_double_extension_rejected[*.zip.ps1]` | ✅ PASSED | Extensión doble `.zip.ps1` rechazada |
| `TestDoubleExtension::test_double_extension_rejected[*.png.scr]` | ✅ PASSED | Extensión doble `.png.scr` rechazada |
| `TestFileTooLarge::test_oversized_file_rejected` | ✅ PASSED | Archivo muy grande rechazado (límite de tamaño) |
| `TestRateLimit::test_rate_limit_enforced` | ✅ PASSED | Rate limiting activo (múltiples requests → 429) |
| `TestPathTraversalSanitization::test_traversal_not_500[../../../etc/passwd]` | ✅ PASSED | Path traversal no causa 500 |
| `TestPathTraversalSanitization::test_traversal_not_500[..\\..\\..]` | ✅ PASSED | Path traversal Windows no causa 500 |
| `TestPathTraversalSanitization::test_traversal_not_500[test/../../secret.exe]` | ✅ PASSED | Path traversal parcial no causa 500 |
| `TestControlCharacters::test_null_byte_rejected` | ✅ PASSED | Null byte en nombre de archivo rechazado |
| `TestControlCharacters::test_rlo_char_rejected` | ✅ PASSED | Carácter RLO (Right-to-Left Override) rechazado |
| `TestHealthNoAuth::test_health_no_auth_never_401` | ✅ PASSED | /health no requiere auth |
| `TestHealthNoAuth::test_health_has_pipeline_mode` | ✅ PASSED | /health reporta modo del pipeline |
| `TestHealthNoAuth::test_health_has_all_components` | ✅ PASSED | /health lista todos los componentes |

**Test fallido: `test_expired_token_rejected`**

Causa raíz: cuando `SUPABASE_URL` y `SUPABASE_JWT_SECRET` no están configurados, el handler de autenticación lanza una excepción no controlada que resulta en HTTP 500 en lugar de retornar HTTP 401 de forma controlada. Este es un bug de seguridad de prioridad media: expone la ausencia de configuración en lugar de fallar de forma segura.

---

## `tests/properties/` — Tests de propiedades (Hypothesis)

Hypothesis genera casos de prueba automáticamente para verificar invariantes del sistema.

### `tests/properties/test_n8n_properties.py`

| Test | Estado | Propiedad verificada |
|------|--------|---------------------|
| `test_prop16_non_alert_always_skip` | ✅ PASSED | Para cualquier resultado no-malicious, n8n siempre lo omite |
| `test_prop17_safe_json_payload_serializable` | ✅ PASSED | El payload de n8n siempre es JSON serializable |
| `test_prop18_disabled_always_false` | ✅ PASSED | Con N8N_ENABLED=False, nunca envía |

### `tests/properties/test_pipeline_properties.py`

| Test | Estado | Propiedad verificada |
|------|--------|---------------------|
| `test_prop1_classify_returns_valid_label` | ✅ PASSED | classify() siempre retorna un label válido |
| `test_prop2_confidence_in_range` | ✅ PASSED | confidence siempre en {High, Medium, Low} |
| `test_prop22_negative_score_suspicious` | ✅ PASSED | Score negativo → SUSPICIOUS (no MALWARE) |
| `test_prop23_high_score_malicious` | ✅ PASSED | Score ≥ umbral → MALWARE |
| `test_prop24_low_score_benign` | ✅ PASSED | Score < umbral → BENIGN |
| `test_prop25_sanitize_filename_safe_chars` | ✅ PASSED | Sanitización de filename preserva caracteres seguros |
| `test_prop26_simple_extension_not_double` | ✅ PASSED | Extensión simple no es detectada como doble |
| `test_prop27_safe_json_always_serializable` | ✅ PASSED | safe_json() siempre produce JSON serializable |
| `test_prop28_rate_limit_eventually_fires` | ✅ PASSED | Rate limit se activa eventualmente para N requests |
| `test_prop29_rate_limit_first_n_true` | ✅ PASSED | Primeras N requests pasan el rate limit |

### `tests/properties/test_quarantine_properties.py`

| Test | Estado | Propiedad verificada |
|------|--------|---------------------|
| `test_prop5_sha256_matches_file` | ✅ PASSED | SHA-256 en metadata siempre coincide con el archivo |
| `test_prop6_original_deleted_after_quarantine` | ✅ PASSED | Archivo original siempre eliminado después de cuarentena |
| `test_prop7_symlink_always_rejected` | ✅ PASSED | Cualquier symlink siempre rechazado |
| `test_prop8_restore_integrity` | ✅ PASSED | Restauración siempre preserva integridad SHA-256 |

### `tests/properties/test_serialization_properties.py`

| Test | Estado | Propiedad verificada |
|------|--------|---------------------|
| `test_prop30_scan_result_roundtrip` | ✅ PASSED | ScanResult roundtrip es idempotente para cualquier input válido |
| `test_prop30b_enums_serialize_as_strings` | ✅ PASSED | Todos los enums se serializan como strings |

---

## Integración con n8n

Los tests de n8n (unitarios y de propiedades) verifican el comportamiento del cliente, no la integración real.
La integración real con un servidor n8n no está disponible en el entorno de test.

**Limitación documentada**: n8n envía alertas solo cuando `label == "malicious"`. El caso de `sample1.exe` (label=BENIGN, operational_status=DANGEROUS) no generaría alerta.

---

## Tests de integración pendientes

1. **Test E2E con servidor n8n real**: verificar que el webhook se activa para casos DANGEROUS.
2. **Test E2E con Supabase real**: verificar persistencia de campos IL y overlay completos.
3. **Test de integración LLM**: verificar que Ollama produce explicaciones coherentes para diferentes tipos de malware.
4. **Test del pipeline con malware real verificado**: ejecutar sobre muestras con ground truth externo (VirusTotal).
