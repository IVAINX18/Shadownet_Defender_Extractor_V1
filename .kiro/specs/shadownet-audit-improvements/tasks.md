# Tasks — ShadowNet Defender: Mejoras de Auditoría

## P0 — Núcleo de Seguridad (Implementar primero)

- [x] 1. Extender configs/settings.py con nuevas variables de entorno
  - [x] 1.1 Agregar QUARANTINE_DIR, ANALYSIS_TIMEOUT_SECONDS, BEHAVIORAL_SHIELD_TIMEOUT_SECONDS, MAX_UPLOAD_MB, RATE_LIMIT_SCANS_PER_MINUTE, SUPABASE_INCIDENTS_TABLE
  - [x] 1.2 Implementar validate_paths(logger) para MODEL_PATH y SCALER_PATH
  - [x] 1.3 Implementar log_config(logger) con enmascarado de secretos
  - Requirement: 10

- [x] 2. Robustecer core/engine.py contra fallos de capas críticas
  - [x] 2.1 Capturar excepción de ONNX → label=UNKNOWN, score=-1.0, operational_status=SUSPICIOUS
  - [x] 2.2 NonPEFileError en .exe/.dll/.sys → operational_status=SUSPICIOUS (no NOT_PE)
  - [x] 2.3 RAW_FALLBACK → registrar extraction_mode en details.diagnostics y confidence=Low
  - [x] 2.4 Envolver cada fase en try/except que agrega {phase}_error=True a details
  - [x] 2.5 Implementar watchdog de timeout de 60s con concurrent.futures
  - Requirement: 7

- [x] 3. Modificar backend/app/services/scan_service.py para clasificar UNKNOWN como suspicious
  - [x] 3.1 En classify_tripartite(): score < 0 → forzar (SUSPICIOUS, MEDIUM)
  - [x] 3.2 En scan_single_file(): label == "UNKNOWN" → ScanResultLabel.SUSPICIOUS
  - [x] 3.3 Calcular SHA-256 del archivo en disco antes de pasarlo al Engine (chunks 64KB)
  - Requirement: 7, 8

- [x] 4. Integrar BehavioralShield en pipeline (Fase 7) en core/engine.py
  - [x] 4.1 Agregar _behavioral_shield = BehavioralShield() en ShadowNetEngine.__init__
  - [x] 4.2 Implementar _resolve_pid(file_path) → Optional[int] via psutil.process_iter
  - [x] 4.3 Implementar _run_behavioral_phase(file_path, result) con timeout de 2s
  - [x] 4.4 Lógica de elevación: risk_score >= 0.5 → DANGEROUS, >= 0.3 → SUSPICIOUS
  - [x] 4.5 Llamar _run_behavioral_phase() al final de scan_file() después de Fase 6 (IL)
  - [x] 4.6 Agregar campo behavioral_analysis: Optional[Dict] al ScanResult DTO en backend/app/schemas/dto.py
  - Requirement: 1

- [x] 5. Crear módulo core/quarantine/manager.py (QuarantineManager)
  - [x] 5.1 Crear core/quarantine/__init__.py con re-export de QuarantineManager
  - [x] 5.2 Implementar QuarantineResult y RestoreResult dataclasses
  - [x] 5.3 Implementar quarantine_file(): SHA-256 antes de mover, renombrar a {SHA256[:8]}_{ts}.quar, crear .meta.json, chmod a-x
  - [x] 5.4 Validaciones de seguridad: rechazar symlinks (SYMLINK_REJECTED) y path traversal (PATH_TRAVERSAL_REJECTED)
  - [x] 5.5 Crear QUARANTINE_DIR con permisos 700 si no existe
  - [x] 5.6 Implementar restore_file() con verificación de integridad SHA-256
  - [x] 5.7 Implementar list_quarantined()
  - [x] 5.8 Logging completo de toda operación
  - Requirement: 2

- [x] 6. Crear ruta API backend/app/api/routes/quarantine.py
  - [x] 6.1 Implementar POST /quarantine/file con autenticación JWT (QuarantineRequest DTO)
  - [x] 6.2 Registrar router en backend/app/main.py
  - Requirement: 2

- [x] 7. Crear módulo core/remediation/engine.py (RemediationEngine)
  - [x] 7.1 Crear core/remediation/__init__.py con re-export de RemediationEngine
  - [x] 7.2 Implementar TerminationResult dataclass
  - [x] 7.3 Implementar terminate_process(pid, reason, scan_id, expected_exe): verificar exe_path, rechazar PID < 10 (PROTECTED_PROCESS_REJECTED), SIGTERM con timeout 3s, escalar a SIGKILL
  - [x] 7.4 Capturar PermissionError y psutil.AccessDenied sin propagar
  - [x] 7.5 Logging completo: PID, exe_path, método, timestamp, scan_id, resultado
  - Requirement: 3

- [x] 8. Crear ruta API backend/app/api/routes/remediation.py
  - [x] 8.1 Implementar POST /remediation/terminate con autenticación JWT obligatoria (TerminateRequest DTO)
  - [x] 8.2 Registrar router en backend/app/main.py
  - Requirement: 3

- [x] 9. Hardening de backend/app/api/routes/scan.py
  - [x] 9.1 Validar extensiones dobles sospechosas → HTTP 400 antes de guardar en disco
  - [x] 9.2 Implementar lectura en streaming con límite MAX_UPLOAD_BYTES
  - [x] 9.3 Sanitizar nombre de archivo (caracteres de control ASCII < 0x20, RLO/LRO Unicode)
  - [x] 9.4 Implementar rate limiting por user_id con sliding window de 60s → HTTP 429
  - [x] 9.5 Limpieza de archivos temporales antiguos si shadownet_uploads contiene > 100 archivos
  - [x] 9.6 Garantizar eliminación del archivo temporal en bloque finally
  - Requirement: 8

## P1 — Integraciones

- [ ] 10. Extender backend/app/integrations/supabase_client.py con telemetría completa
  - [ ] 10.1 Implementar _safe_json(obj) para serialización segura de NaN/Inf
  - [ ] 10.2 Ampliar record en save_scan() con 16 campos nuevos (operational_status, sha256, overlay_analysis, yara_matches, il_behavioral, dotnet_analysis, detection_phases, was_unpacked, is_dotnet, obfuscator_detected, obfuscator_name, injection_detected, persistence_detected, networking_detected, credential_theft_detected, behavioral_analysis)
  - [ ] 10.3 Implementar idempotencia por sha256 + ventana 60s
  - [ ] 10.4 Implementar save_incident() para DANGEROUS → tabla incidents
  - [ ] 10.5 Fallback a offline_service si Supabase falla (sin propagar excepción)
  - Requirement: 4

- [ ] 11. Crear script SQL de migración docs/supabase_migration.sql
  - [ ] 11.1 ALTER TABLE scan_results con las 16 columnas nuevas
  - [ ] 11.2 CREATE TABLE incidents con índices
  - [ ] 11.3 Índices en scan_results (sha256, operational_status)
  - Requirement: 4

- [ ] 12. Mejorar core/integrations/n8n_client.py
  - [ ] 12.1 Cambiar condición de disparo: result=="malicious" OR operational_status=="DANGEROUS"
  - [ ] 12.2 Extender payload con operational_status, risk_score, risk_level, detection_phases, top_family, injection_detected, persistence_detected
  - [ ] 12.3 Implementar retry exponencial (1s, 2s) en HTTP >= 500 (máx 2 reintentos)
  - [ ] 12.4 Sanitizar payload con _safe_json antes de enviar
  - Requirement: 5

- [ ] 13. Mejorar backend/app/services/realtime_service.py
  - [ ] 13.1 Ordenar procesos por CPU y seleccionar top-20 para análisis behavioral
  - [ ] 13.2 Implementar _enrich_with_behavioral() invocando BehavioralShield.analyze_process(pid)
  - [ ] 13.3 Añadir behavioral_risk_score, behavioral_is_suspicious, suspicious_actions, risk_reason a cada proceso
  - [ ] 13.4 Diferenciación risk_reason: "behavioral" vs "performance"
  - [ ] 13.5 Timeout global de 10s con concurrent.futures
  - [ ] 13.6 Procesos con AccessDenied → risk_level="unknown", access_denied=True
  - Requirement: 6

## P2 — Tests y Observabilidad

- [ ] 14. Crear infraestructura de tests
  - [ ] 14.1 Crear tests/__init__.py, tests/conftest.py con fixtures base (tmp_path, mock_engine, TestClient)
  - [ ] 14.2 Crear subdirectorios tests/unit/, tests/integration/, tests/security/, tests/properties/
  - [ ] 14.3 Crear tests/fixtures/ con sample_pe.exe (PE benigno mínimo para tests)
  - Requirement: 9

- [ ] 15. Tests unitarios: extractor y engine
  - [ ] 15.1 tests/unit/test_extractor.py: vector 2381 dimensiones, NonPEFileError en no-PE, NonPEFileError en vacío, RAW_FALLBACK no-cero
  - [ ] 15.2 tests/unit/test_engine.py: YARA match → MALWARE, ONNX falla → UNKNOWN/SUSPICIOUS, no-PE .exe → SUSPICIOUS, elevación behavioral DANGEROUS/SUSPICIOUS, fase falla → pipeline continúa
  - Requirement: 9

- [ ] 16. Tests unitarios: quarantine y remediation
  - [ ] 16.1 tests/unit/test_quarantine.py: quarantine mueve archivo, SHA-256 en meta, symlink rechazado, path traversal rechazado, restore verifica SHA-256, directorio 700
  - [ ] 16.2 tests/unit/test_remediation.py: PID < 10 rechazado, exe_path mismatch rechazado, PermissionError no propagado
  - Requirement: 9

- [ ] 17. Tests de integración y serialización
  - [ ] 17.1 tests/integration/test_pipeline_e2e.py: accuracy sobre data/test_set/ (X_test.npy, y_test.npy)
  - [ ] 17.2 tests/integration/test_supabase_client.py: telemetría completa, incidents en DANGEROUS, fallback offline, idempotencia sha256
  - [ ] 17.3 tests/unit/test_scan_result_serde.py: round-trip serialización ScanResult
  - [ ] 17.4 tests/unit/test_settings.py: defaults presentes, secretos enmascarados en log_config
  - Requirement: 9

- [ ] 18. Tests de seguridad y propiedades
  - [ ] 18.1 tests/security/test_backend_security.py: path traversal sanitizado, archivo > MAX_UPLOAD_BYTES → 413, sin JWT → 401, JWT expirado → 401, doble extensión → 400, rate limit → 429, cleanup en excepción
  - [ ] 18.2 tests/properties/test_pipeline_properties.py: Properties 1, 2, 22, 23, 24, 25, 26, 27, 28, 29 con Hypothesis
  - [ ] 18.3 tests/properties/test_quarantine_properties.py: Properties 5, 6, 7, 8
  - [ ] 18.4 tests/properties/test_n8n_properties.py: Properties 16, 17, 18
  - [ ] 18.5 tests/properties/test_serialization_properties.py: Property 30
  - Requirement: 9

- [ ] 19. Health endpoint extendido en backend/app/main.py o backend/app/api/routes/health.py
  - [ ] 19.1 Implementar _check_components(): onnx_model, yara_scanner, supabase, n8n, psutil, offline_queue_size
  - [ ] 19.2 Implementar _compute_pipeline_mode(): full / degraded / minimal
  - [ ] 19.3 Retornar HTTP 503 si componente crítico (onnx_model o yara_scanner) está degradado
  - [ ] 19.4 Eliminar autenticación JWT del endpoint GET /health
  - Requirement: 11

## P3 — Despliegue

- [ ] 20. Crear scripts de despliegue
  - [ ] 20.1 Crear deploy/shadownet.service (systemd unit: Restart=on-failure, EnvironmentFile, ExecStartPre para verificar modelo)
  - [ ] 20.2 Crear deploy/install_linux.sh (Python >= 3.10, no-root check, usuario shadownet, pip install, systemctl enable+start)
  - [ ] 20.3 Crear deploy/install_windows.ps1 (Python >= 3.10, pip install, NSSM service registration)
  - Requirement: 12

- [ ] 21. Checkpoint final de validación
  - [ ] 21.1 Ejecutar pytest --tb=short y verificar que todos los tests pasan
  - [ ] 21.2 Verificar que getDiagnostics no reporta errores en archivos modificados
  - [ ] 21.3 Verificar que GET /health responde correctamente sin JWT
