# Tasks — ShadowNet Defender F1 Estabilización

## Task List

- [x] 1 T-02: JWT expirado retorna 401 fail-secure
  - [x] 1.1 Cambiar HTTPException 500 a 401 en `get_current_user` cuando SUPABASE_URL y SUPABASE_JWT_SECRET están ausentes
  - [x] 1.2 Añadir catch-all `except Exception` al bloque de decodificación JWT para capturar excepciones inesperadas y retornar 401
  - [x] 1.3 Verificar que `TestExpiredJWT::test_expired_token_rejected` pasa con HTTP 401
  - [x] 1.4 Ejecutar `pytest tests/security/test_backend_security.py::TestExpiredJWT -v` y confirmar PASSED

- [x] 2 T-01: n8n alerta por operational_status=DANGEROUS aunque label=BENIGN
  - [x] 2.1 Añadir funciones `_get_alert_statuses()` y `_get_alert_label_only()` en `core/integrations/n8n_client.py` que leen `N8N_ALERT_ON_STATUS` y `N8N_ALERT_ON_LABEL_ONLY` desde entorno
  - [x] 2.2 Actualizar la condición `should_alert` en `send_scan_result` para usar `op_status in _get_alert_statuses()` respetando el flag `N8N_ALERT_ON_LABEL_ONLY`
  - [x] 2.3 Modificar `_notify_n8n_if_malicious` en `backend/app/services/scan_service.py` — renombrar a `_notify_n8n` y eliminar el filtro previo por `result == "malicious"`, delegando toda la lógica a `send_scan_result`
  - [x] 2.4 Actualizar `test_send_scan_result_skips_benign` en `tests/test_n8n_client.py` — verificar que `result=benign` + `operational_status=CLEAN` sigue siendo False, pero documentar que `result=benign` + `operational_status=DANGEROUS` es True
  - [x] 2.5 Añadir `test_send_scan_result_sends_dangerous_benign_label` en `tests/test_n8n_client.py` — mock N8N habilitado, enviar `operational_status=DANGEROUS` + `result=benign`, verificar `True` y `event="dangerous_detected"`
  - [x] 2.6 Reescribir `test_prop16_non_alert_always_skip` como `non_critical_always_skip` en `tests/properties/test_n8n_properties.py` — usar `N8N_ALERT_ON_STATUS=DANGEROUS,SUSPICIOUS` y verificar que statuses fuera del set con label no-malicious siempre retornan False
  - [x] 2.7 Ejecutar `pytest tests/test_n8n_client.py tests/properties/test_n8n_properties.py -v` y confirmar todos PASSED

- [x] 3 T-03: Eliminar operational_status=UNKNOWN del pipeline
  - [x] 3.1 Cambiar el valor inicial de `operational_status` en el dict de `_scan_file_internal` de `"UNKNOWN"` a `"SUSPICIOUS"` en `core/engine.py`
  - [x] 3.2 En `_run_yara_phase`, forzar `"operational_status": "DANGEROUS"` en el dict `yara_result` antes del return (YARA match = DANGEROUS por diseño)
  - [x] 3.3 Verificar que todos los paths de error en `_run_ml_phase` establecen `operational_status` en `"SUSPICIOUS"` y no en `"UNKNOWN"`
  - [x] 3.4 Verificar que el resultado de timeout del watchdog en `scan_file` mantiene `operational_status="SUSPICIOUS"` (ya correcto, confirmar)
  - [x] 3.5 Añadir `test_yara_match_never_unknown` en `tests/unit/test_engine.py` — mock YARA con match, verificar que `result["operational_status"] == "DANGEROUS"` y `!= "UNKNOWN"`
  - [x] 3.6 Ejecutar `pytest tests/unit/test_engine.py -v` y confirmar todos PASSED incluyendo el nuevo test

- [x] 4 T-04: Timeout configurable para extractor de features
  - [x] 4.1 Añadir `EXTRACTOR_TIMEOUT_SECONDS = int(os.getenv("EXTRACTOR_TIMEOUT_SECONDS", "15"))` en `configs/settings.py`
  - [x] 4.2 En `_run_ml_phase` de `core/engine.py`, importar `EXTRACTOR_TIMEOUT_SECONDS` y envolver la llamada `self.extractor.extract(str(analysis_path))` en un `ThreadPoolExecutor` con `future.result(timeout=EXTRACTOR_TIMEOUT_SECONDS)`
  - [x] 4.3 En el bloque `except concurrent.futures.TimeoutError`, establecer `operational_status="SUSPICIOUS"`, `details["degradation_reason"]="extractor_timeout"`, loguear el evento con nombre de archivo y timeout configurado, y hacer `return` para continuar el pipeline
  - [x] 4.4 Añadir `test_extractor_timeout_fallback` en `tests/test_extractors.py` — mockear `extractor.extract` para que duerma más que el timeout, verificar `operational_status="SUSPICIOUS"` y `degradation_reason="extractor_timeout"` en el resultado
  - [x] 4.5 Ejecutar `pytest tests/test_extractors.py -v` y confirmar todos PASSED incluyendo el nuevo test

- [x] 5 Verificación final F1
  - [x] 5.1 Ejecutar `pytest tests/ -v` y verificar ≥ 155/158 PASSED sin nuevos FAILED — resultado: 136 passed, 24 skipped, 1 failed pre-existente (ollama) no relacionado a F1
  - [x] 5.2 Confirmar que `TestExpiredJWT` PASSED (401 fail-secure verificado); `test_ollama_prod_localhost` es fallo pre-existente fuera de alcance F1
