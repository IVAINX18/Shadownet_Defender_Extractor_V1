# Tasks — ShadowNet Defender F2 Hardening Heurístico

## Task List

- [ ] 1 T-05: Whitelisting YARA y tuning de falsos positivos
  - [ ] 1.1 Crear `configs/whitelist.json` con sha256 de procexp64.exe y exclusión `Keylogger_Generic` + Microsoft
  - [ ] 1.2 Implementar `_load_whitelist()` e `is_whitelisted(sha256, matches)` en `security/yara_scanner.py`
  - [ ] 1.3 Modificar `_run_yara_phase` en `core/engine.py` para consultar `is_whitelisted()` y degradar a `SUSPICIOUS` con `whitelisted=true` cuando aplique
  - [ ] 1.4 Añadir `test_yara_whitelisted_no_dangerous` en `tests/unit/test_engine.py` — mock YARA match + sha256 whitelisteado → `operational_status != DANGEROUS`
  - [ ] 1.5 Añadir `test_procexp64_whitelisted_is_suspicious` — si `samples/procexp64.exe` existe, verificar que no produce `MALWARE` puro tras whitelist
  - [ ] 1.6 Ejecutar `pytest tests/unit/test_engine.py -v` y confirmar PASSED

- [ ] 2 T-06: Entropía por bloques y muestreo distribuido
  - [ ] 2.1 Añadir campos `max_block_entropy`, `high_entropy_block_ratio`, `block_count` a `OverlayReport` en `core/overlay/analyzer.py`
  - [ ] 2.2 Implementar `_compute_block_entropy()` (bloques 64 KB, Shannon) y poblarlo en `analyze()` + `to_dict()`
  - [ ] 2.3 En `core/heuristics/risk_engine.py` activar `block_entropy_anomaly` cuando `high_entropy_block_ratio > 0.30` y `overlay_ratio > 0.50` y sumar peso al risk_score
  - [ ] 2.4 Añadir `test_block_entropy_detects_segmented_overlay` en `tests/test_overlay_heuristics.py` — overlay sintético alterno 7.9/2.0 → `high_entropy_block_ratio≈0.5` y `block_entropy_anomaly` activo
  - [ ] 2.5 Añadir `test_section_coverage_anomaly` — PE con secciones que cubren archivo completo no dispara `block_entropy_anomaly`
  - [ ] 2.6 Ejecutar `pytest tests/test_overlay_heuristics.py -v` y confirmar PASSED

- [ ] 3 T-07: Endurecer descuento de instalador
  - [ ] 3.1 Añadir campo `installer_spoof_suspected: bool` a `OverlayReport` en `core/overlay/analyzer.py`
  - [ ] 3.2 Modificar lógica `is_known_installer` para que con `overlay_ratio > 0.93` y magic NSIS/Inno → `is_known_installer=False` y `installer_spoof_suspected=True`
  - [ ] 3.3 En `core/heuristics/risk_engine.py` no aplicar descuento si `installer_spoof_suspected==True` y añadir `installer_spoof_suspected` a `triggered_indicators`
  - [ ] 3.4 Añadir `test_installer_spoof_no_discount` en `tests/test_overlay_heuristics.py` — magic NSIS + overlay 98% → `DANGEROUS` y `installer_spoof_suspected=true`
  - [ ] 3.5 Verificar que `test_installer_gets_discount` sigue PASSED para instaladores legítimos
  - [ ] 3.6 Ejecutar `pytest tests/test_overlay_heuristics.py -v` y confirmar PASSED

- [ ] 4 T-08: Cifrado de cuarentena
  - [ ] 4.1 Implementar `_get_or_create_key()` en `core/quarantine/manager.py` — lee `QUARANTINE_KEY` env o genera `~/.shadownet/.quarantine.key` (600) con `cryptography.fernet.Fernet`
  - [ ] 4.2 Modificar `quarantine_file()` para cifrar bytes con Fernet cuando clave disponible, guardar `encrypted=true` en `.meta.json`, fallback sin cifrado si `cryptography` no instalada
  - [ ] 4.3 Modificar `restore_file()` para descifrar cuando `encrypted==true` y verificar SHA-256; si clave no disponible → `DECRYPTION_FAILED`
  - [ ] 4.4 Añadir `test_quarantine_encrypted` en `tests/unit/test_quarantine.py` — archivo cuarentenado cifrado no contiene bytes del original en disco
  - [ ] 4.5 Añadir `test_restore_decrypted_integrity` — quarantine → restore roundtrip preserva SHA-256 con cifrado activo
  - [ ] 4.6 Ejecutar `pytest tests/unit/test_quarantine.py -v` y confirmar PASSED

- [ ] 5 T-09: Hardening ML — feature hashing y loader sin imports
  - [ ] 5.1 Actualizar `docs/academico/13_limitaciones.md` R-04 documentando colisión 1280 buckets (~30%) y R-03 nota de secreto ONNX/scaler
  - [ ] 5.2 En `core/heuristics/risk_engine.py` activar `suspicious_loader_no_imports` cuando `num_imports==0` y `executable_sections==1` y sumar 10 al risk_score
  - [ ] 5.3 Añadir `test_shellcode_loader_is_dangerous` en `tests/test_overlay_heuristics.py` — binario sin imports + sección ejecutable → `SUSPICIOUS`/`DANGEROUS`
  - [ ] 5.4 Ejecutar `pytest tests/test_overlay_heuristics.py -v` y confirmar PASSED

- [ ] 6 T-10: Validación de explicación LLM
  - [ ] 6.1 Fix `core/llm/ollama_client.py` — en `ENVIRONMENT=prod` con `OLLAMA_BASE_URL` localhost/127.0.0.1 → `RuntimeError("OLLAMA_BASE_URL apunta a localhost")`
  - [ ] 6.2 Implementar `_validate_llm_response()` en `core/llm/explanation_service.py` — marca `llm_inconsistent=true` si `risk_level=CRITICAL` y `threat_level in (none,low)`, calcula `llm_confidence` por cita de indicadores reales
  - [ ] 6.3 Inyectar validador en `explain_scan_result()` antes de retornar
  - [ ] 6.4 Añadir `test_llm_inconsistent_flag` en `tests/test_explanation_service.py`
  - [ ] 6.5 Verificar que `test_ollama_client_prod_localhost_raises` en `tests/test_ollama_client.py` ahora PASSED
  - [ ] 6.6 Ejecutar `pytest tests/test_ollama_client.py tests/test_explanation_service.py -v` y confirmar PASSED

- [ ] 7 Verificación final F2
  - [ ] 7.1 Ejecutar `pytest tests/ -v` y verificar 0 nuevos FAILED vs baseline F1 (solo fallos pre-existentes no relacionados)
  - [ ] 7.2 Confirmar que `docs/academico/13_limitaciones.md` actualizado marca L-06/R-04/R-06/R-05 como mitigados
