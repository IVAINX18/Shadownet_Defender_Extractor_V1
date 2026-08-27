# Pruebas Unitarias — Documentación

> Suite ejecutada: `python -m pytest tests/ -v` en 2026-08-18.
> Resultado: 151 passed, 2 failed, 5 skipped de 158 tests en 16.76 segundos.

---

## Suites unitarias disponibles

### `tests/unit/test_engine.py`

**Objetivo**: Verificar el comportamiento del motor central ante condiciones adversas.

| Test | Estado | Qué verifica |
|------|--------|--------------|
| `TestEngineYARA::test_yara_match_returns_malware` | ✅ PASSED | Un match YARA produce resultado MALWARE inmediato |
| `TestEngineONNXFail::test_onnx_failure_suspicious` | ✅ PASSED | Si ONNX falla, resultado es SUSPICIOUS (no crash) |
| `TestEngineNonPEExe::test_non_pe_exe_suspicious` | ✅ PASSED | Archivo .exe que no es PE válido → SUSPICIOUS |
| `TestEngineBehavioralElevation::test_behavioral_elevation_dangerous` | ✅ PASSED | Indicadores heurísticos elevan status a DANGEROUS |
| `TestEngineBehavioralElevation::test_behavioral_elevation_suspicious` | ✅ PASSED | Indicadores medios elevan a SUSPICIOUS |
| `TestEnginePhaseFaultTolerance::test_phase_failure_continues` | ✅ PASSED | Fallo en una fase no detiene el pipeline |

**Cobertura**: Fault tolerance, YARA early exit, elevación heurística, manejo de no-PE.

---

### `tests/unit/test_extractor.py`

**Objetivo**: Verificar las dimensiones y modos del extractor de features.

| Test | Estado | Qué verifica |
|------|--------|--------------|
| `TestExtractorDimensions::test_vector_2381_dimensions` | ⏭️ SKIPPED | Vector resultante tiene exactamente 2381 dims |
| `TestExtractorNonPEErrors::test_non_pe_raises_error` | ⏭️ SKIPPED | Archivo no-PE lanza excepción controlada |
| `TestExtractorNonPEErrors::test_empty_file_raises_error` | ⏭️ SKIPPED | Archivo vacío lanza excepción controlada |
| `TestExtractorRawFallback::test_raw_fallback_not_zero` | ⏭️ SKIPPED | Modo RAW_FALLBACK produce vector no-cero |

**Razón del skip**: Los tests requieren fixtures de archivos PE reales no disponibles en el entorno CI.

---

### `tests/unit/test_quarantine.py`

**Objetivo**: Verificar el aislamiento seguro de archivos.

| Test | Estado | Qué verifica |
|------|--------|--------------|
| `TestQuarantineFile::test_quarantine_moves_file` | ✅ PASSED | El archivo es movido al directorio de cuarentena |
| `TestQuarantineFile::test_quarantine_sha256_in_meta` | ✅ PASSED | Metadatos incluyen SHA-256 del archivo |
| `TestQuarantineSecurityRejections::test_quarantine_rejects_symlink` | ✅ PASSED | Symlinks son rechazados (seguridad) |
| `TestQuarantineSecurityRejections::test_quarantine_rejects_traversal` | ✅ PASSED | Path traversal (`../`) rechazado |
| `TestQuarantineRestore::test_restore_integrity` | ✅ PASSED | Restauración verifica SHA-256 (integridad) |
| `TestQuarantineDirectory::test_creates_dir_700` | ✅ PASSED | Directorio creado con permisos 700 (restrictivos) |

**Cobertura**: Seguridad del sistema de archivos, integridad criptográfica, control de acceso.

---

### `tests/unit/test_remediation.py`

**Objetivo**: Verificar la terminación segura de procesos.

| Test | Estado | Qué verifica |
|------|--------|--------------|
| `TestProtectedProcessRejection::test_rejects_pid_below_10[0]` | ✅ PASSED | PID 0 rechazado (proceso sistema) |
| `TestProtectedProcessRejection::test_rejects_pid_below_10[1]` | ✅ PASSED | PID 1 rechazado |
| `TestProtectedProcessRejection::test_rejects_pid_below_10[2]` | ✅ PASSED | PID 2 rechazado |
| `TestProtectedProcessRejection::test_rejects_pid_below_10[5]` | ✅ PASSED | PID 5 rechazado |
| `TestProtectedProcessRejection::test_rejects_pid_below_10[9]` | ✅ PASSED | PID 9 rechazado |
| `TestExeMismatch::test_exe_mismatch_rejected` | ✅ PASSED | Proceso con exe_path diferente al esperado es rechazado |
| `TestPermissionErrorNotPropagated::test_permission_error_not_propagated` | ✅ PASSED | PermissionError no se propaga al caller |

**Cobertura**: Protección de procesos del sistema, verificación de identidad de proceso, manejo graceful de errores de permisos.

---

### `tests/unit/test_settings.py`

**Objetivo**: Verificar los valores por defecto de configuración.

| Test | Estado | Qué verifica |
|------|--------|--------------|
| `test_quarantine_dir_default` | ✅ PASSED | Directorio cuarentena por defecto correcto |
| `test_analysis_timeout_default` | ✅ PASSED | Timeout de análisis por defecto |
| `test_behavioral_timeout_default` | ✅ PASSED | Timeout conductual por defecto |
| `test_rate_limit_default` | ✅ PASSED | Rate limit por defecto |
| `test_feature_dimension` | ✅ PASSED | Dimensión de features = 2381 |
| `test_incidents_table` | ✅ PASSED | Nombre de tabla de incidentes en Supabase |
| `TestLogConfig::test_secrets_masked` | ✅ PASSED | Secrets (keys, tokens) no aparecen en logs |

**Cobertura**: Configuración por defecto, seguridad de logs.

---

### `tests/unit/test_scan_result_serde.py`

**Objetivo**: Verificar serialización y deserialización del resultado del scan.

| Test | Estado | Qué verifica |
|------|--------|--------------|
| `TestScanResultSerde::test_roundtrip_full` | ✅ PASSED | ScanResult → dict → ScanResult es idempotente |
| `TestScanResultSerde::test_enum_serialization_as_string` | ✅ PASSED | Enums se serializan como strings (JSON-safe) |
| `TestScanResultSerde::test_optional_fields_none` | ✅ PASSED | Campos opcionales pueden ser None |

---

### `tests/test_extractors.py`

**Objetivo**: Verificar bloques individuales del extractor de features.

| Test | Estado | Qué verifica |
|------|--------|--------------|
| `test_byte_histogram` | ✅ PASSED | ByteHistogram produce 256 features |
| `test_byte_entropy` | ✅ PASSED | ByteEntropy produce 256 features |
| `test_imports_dim` | ✅ PASSED | Imports produce 1280 features |
| `test_header_dim` | ✅ PASSED | Header produce 62 features |
| `test_section_dim` | ✅ PASSED | Section produce 255 features |
| `test_string_extractor` | ✅ PASSED | StringExtractor produce features de strings |
| `test_raw_fallback_non_pe` | ✅ PASSED | RAW_FALLBACK funciona para no-PE |
| `test_distributed_sampling` | ✅ PASSED | Muestreo distribuido funciona para archivos grandes |
| `test_packer_detection` | ✅ PASSED | Indicadores de packer detectados correctamente |

---

### `tests/test_il_analyzer.py` (37 tests, todos PASSED)

**Objetivo**: Verificar el análisis IL Behavioral para 15 categorías.

Todos los tests pasaron. Categorías verificadas: Reflection (M2), Dynamic Loading (M3), Injection (M5), Persistence (M6), Networking (M7), Command Execution (M8), Credential Theft (M9), Worm (M10), Stealer, RAT, Threat Score calculation, Status elevation, XWorm family detection, AgentTesla family detection, to_dict serialization, performance (archivos grandes).

---

### `tests/test_overlay_heuristics.py` (20 tests, todos PASSED)

**Objetivo**: Verificar la detección de overlays y el Risk Engine.

Tests clave:
- `test_sample1_evasion_scenario`: verifica el caso concreto documentado en `05_hallazgo_multicapa.md`
- `test_ml_benign_critical_heuristic_is_dangerous`: ML=benign + heurística crítica → DANGEROUS
- `test_dropper_scores_critical`: patrón dropper produce score CRITICAL
- `test_installer_gets_discount`: NSIS/InnoSetup reduce el score (menos falsos positivos)

---

## Cobertura de código

No se ejecutó `pytest --cov` durante la auditoría. La cobertura cuantitativa (%) requiere el paquete `pytest-cov` y está pendiente.

**Áreas conocidas sin cobertura de tests**:
- `core/dynamic/process_monitor.py` (BehavioralShield): código no integrado al pipeline, sin tests unitarios directos
- `backend/app/services/realtime_service.py`: sin tests dedicados identificados
- Rutas de integración n8n con `operational_status == "DANGEROUS"` y `label == "BENIGN"` (el bug documentado en H-01)
