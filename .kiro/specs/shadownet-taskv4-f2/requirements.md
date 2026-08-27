# Requirements Document — ShadowNet Defender F2 Hardening Heurístico

## Introduction

Este documento cubre la fase **F2 — Hardening heurístico** de ShadowNet Defender (TaskV4), compuesta por seis tareas (T-05 a T-10) que endurecen las capas de detección sin modificar el modelo ML ni el contrato de 2381 dimensiones. F2 asume **F1 Estabilización completado** (T-01..T-04 verdes): `operational_status` ya no es `UNKNOWN`, n8n alerta por `DANGEROUS`, JWT retorna 401 fail-secure y el extractor tiene timeout configurable.

F2 corrige: falsos positivos YARA sobre software legítimo (H-03/L-06), cobertura reducida en archivos >10 MB (H-08/L-09), evasión por overlay segmentado/instalador falso (R-01/R-02/CE-01/CE-02), cuarentena sin cifrado (R-06), superficie adversarial del modelo (R-03/R-04/CE-03) y dependencia no validada de Ollama (R-05).

Artefactos `scaler.pkl` y `best_model.onnx` **no se modifican** en T-05..T-10 salvo nota explícita en R-04 (requiere reentrenamiento, fuera de alcance F2).

---

## Glossary

- **YARA_Scanner**: `security/yara_scanner.py` — escaneo determinista con 4 archivos de reglas (trojan/spyware/worm/ransomware).
- **Whitelist**: `configs/whitelist.json` — hashes SHA-256 de software conocido-benigno + reglas de exclusión por YARA.
- **OverlayAnalyzer**: `core/overlay/analyzer.py` — calcula `overlay_ratio`, `overlay_entropy`, `embedded_pe`, `is_known_installer`.
- **RiskEngine**: `core/heuristics/` — `HeuristicRiskEngine.assess()` produce `operational_status`/`risk_level`/`risk_score`.
- **QuarantineManager**: `core/quarantine/manager.py` — mueve archivos a `QUARANTINE_DIR` con `.meta.json`.
- **Extractor**: `extractors/extractor.py` — `PEFeatureExtractor` (2381 dims, PE_FASTLOAD para >10 MB).
- **FeatureHashing**: `extractors/imports.py` — 1280 buckets para APIs importadas.
- **OllamaClient**: `core/llm/ollama_client.py` — wrapper OpenAI-compatible sobre Ollama local.
- **ExplanationService**: `core/llm/explanation_service.py` — timeout 30s, parseo JSON/markdown.
- **PromptBuilder**: `core/llm/prompt_builder.py` — `extract_scan_summary()` + `build_llm_prompt()` con guardrails.
- **DANGEROUS/SUSPICIOUS/CLEAN**: valores válidos de `operational_status` (F1 ya eliminó `UNKNOWN`).
- **BlockEntropy**: entropía Shannon por bloques de 64 KB del overlay (nuevo en T-06).
- **InstallerSpoof**: binario que incluye magic bytes NSIS/InnoSetup para activar descuento de instalador (R-02).

---

## Requirements

### Requirement 1: Whitelisting YARA y tuning de falsos positivos (T-05)

**User Story:** Como operador SOC, quiero que Process Explorer y otras herramientas legítimas no disparen `Keylogger_Generic` como MALWARE, para que la tasa de FPR sea operativa en endpoints con software de administración.

#### Acceptance Criteria

1. WHEN `procexp64.exe` (SHA-256 whitelisteado) activa `Keylogger_Generic`, THE YARA_Scanner SHALL reportar el match en `yara_matches` pero THE RiskEngine SHALL degradar el veredicto a `SUSPICIOUS` con `whitelisted=true` en `heuristic_assessment` en lugar de `DANGEROUS`.
2. THE System SHALL cargar `configs/whitelist.json` en startup con estructura `{"sha256": ["<hash>"], "yara_exclusions": [{"rule": "Keylogger_Generic", "company": "Microsoft"}]}` y aplicarlo en cada scan.
3. IF `whitelist.json` no existe o es inválido, THEN THE System SHALL continuar sin whitelist y loguear WARNING sin lanzar excepción.
4. THE YaraScanner SHALL exponer `is_whitelisted(sha256, yara_matches)` para que RiskEngine lo consulte sin acoplar lógica de hashing.
5. WHEN una regla YARA genérica activa sobre un binario whitelisteado, THE System SHALL incluir `whitelist_hit=true` en el payload n8n y no elevar `event` a `malware_critical`.
6. THE System SHALL documentar FPR YARA medido sobre corpus benigno cuando T-13 esté disponible; mientras tanto, el test de regresión `procexp64.exe` no debe producir `MALWARE` puro.

### Requirement 2: Entropía por bloques y muestreo distribuido (T-06)

**User Story:** Como analista forense, quiero que un overlay segmentado (cifrado intercalado con datos de baja entropía) sea detectado aunque su entropía promedio quede bajo 7.2.

#### Acceptance Criteria

1. THE OverlayAnalyzer SHALL calcular `max_block_entropy` y `high_entropy_block_ratio` sobre bloques de 64 KB del overlay además de `overlay_entropy` global.
2. WHEN `high_entropy_block_ratio > 0.30` y `overlay_ratio > 0.50`, THE RiskEngine SHALL activar indicador `block_entropy_anomaly=true` y sumar peso al `risk_score` aunque `overlay_entropy` promedio sea <7.2.
3. THE Extractor SHALL documentar que CE-02 (secciones extras para reducir `overlay_ratio`) es detectado vía `anomalous_sections` y `virtual/raw size mismatch`; el test de regresión debe verificar `test_no_imports_raises_score` y nuevo `test_section_coverage_anomaly`.
4. THE RiskEngine SHALL exponer `triggered_indicators` que incluya `block_entropy_anomaly` cuando aplique, visible en `ScanResult.heuristic_assessment`.
5. THE OverlayAnalyzer SHALL mantener compatibilidad: `overlay_entropy` global sigue presente; nuevos campos son aditivos.
6. WHEN el overlay es <64 KB, THE OverlayAnalyzer SHALL tratarlo como un solo bloque sin error.

### Requirement 3: Endurecer descuento de instalador (T-07)

**User Story:** Como ingeniero de detección, quiero que un binario con 98% overlay no obtenga descuento de instalador aunque contenga magic bytes NSIS, para cerrar la evasión R-02.

#### Acceptance Criteria

1. THE OverlayAnalyzer SHALL aplicar descuento `is_known_installer` solo si `overlay_ratio < 0.90` Y `installer_type in ("NSIS","InnoSetup")` Y estructura de secciones coincide con patrón de instalador.
2. WHEN `overlay_ratio > 0.93` aunque haya magic NSIS/InnoSetup, THE RiskEngine SHALL marcar `installer_spoof_suspected=true` y NO aplicar descuento; el `risk_score` permanece `CRITICAL` si otros indicadores lo dictan.
3. THE RiskEngine SHALL test `test_installer_spoof_no_discount` — binario sintético con magic NSIS + overlay 98% → `operational_status=DANGEROUS` y `installer_spoof_suspected=true`.
4. THE System SHALL loguear `installer_spoof_suspected` en WARNING cuando se detecte.
5. THE existing test `test_installer_gets_discount` SHALL seguir pasando para instaladores legítimos (overlay <50%).

### Requirement 4: Cifrado de cuarentena (T-08)

**User Story:** Como operador de seguridad, quiero que los archivos en `~/.shadownet/quarantine/` no sean legibles sin la clave de cuarentena, para que un atacante con acceso al FS no pueda extraer el malware.

#### Acceptance Criteria

1. THE QuarantineManager SHALL cifrar el archivo `.quar` con `cryptography.fernet.Fernet` usando clave derivada de `QUARANTINE_KEY` env o generada y almacenada en `~/.shadownet/.quarantine.key` con permisos 600.
2. WHEN `quarantine_file()` es llamado, THE QuarantineManager SHALL escribir el archivo cifrado y el `.meta.json` con `sha256` del original, `encrypted=true` y `key_id`.
3. THE QuarantineManager SHALL implementar `restore_file()` que descifre y verifique `SHA-256` del original; si `encrypted=true` y clave no disponible, retornar `error="DECRYPTION_FAILED"`.
4. IF `cryptography` no está instalada, THEN THE QuarantineManager SHALL fallback a modo sin cifrado con `encrypted=false` y loguear WARNING.
5. THE Quarantine directory SHALL seguir con permisos 700; la clave con 600.
6. THE existing tests `tests/unit/test_quarantine.py` SHALL seguir pasando; nuevo test `test_quarantine_encrypted` verifica que el archivo en disco no contiene bytes del original.

### Requirement 5: Hardening ML — feature hashing y loader sin imports (T-09)

**User Story:** Como investigador adversarial, quiero documentado el riesgo de colisiones en 1280 buckets y verificado que un loader sin imports no evade el sistema.

#### Acceptance Criteria

1. THE Docs SHALL actualizar `13_limitaciones.md` R-04 documentando colisión 1280 buckets como limitación conocida; cambiar a 2048 buckets queda explícitamente fuera de alcance F2 (requiere reentrenamiento + nuevo `scaler.pkl` + `best_model.onnx`).
2. WHEN un binario tiene `num_imports==0` y `executable_sections==1`, THE RiskEngine SHALL activar `suspicious_loader_no_imports=true` y elevar `risk_score` aunque ML label sea `BENIGN` (refuerzo de `test_no_imports_raises_score`).
3. THE System SHALL test `test_shellcode_loader_is_dangerous` — binario sintético sin imports + sección ejecutable → `operational_status` en `{SUSPICIOUS,DANGEROUS}`.
4. THE Docs SHALL añadir nota R-03: artefactos ONNX/scaler deben tratarse como secreto; exposición permite ataque adversarial.
5. THE RiskEngine SHALL no modificar `label`/`score` ML; solo `operational_status`.

### Requirement 6: Validación de explicación LLM (T-10)

**User Story:** Como analista SOC, quiero que una explicación LLM que contradiga `risk_level=CRITICAL` con `threat_level=none` sea marcada inconsistente, para no confiar en narrativa alucinada.

#### Acceptance Criteria

1. THE ExplanationService SHALL validar post-LLM: si `risk_level=CRITICAL` y `threat_level in ("none","low")`, marcar `llm_inconsistent=true` en el `ScanResult.llm_explanation`.
2. THE ExplanationService SHALL calcular `llm_confidence` basado en si la respuesta cita al menos un indicador real del `ScanResult` (ej. `overlay_ratio`, `yara_matches`, `injection_detected`).
3. THE OllamaClient SHALL fix `test_ollama_client_prod_localhost_raises` — `ENVIRONMENT=prod` + `OLLAMA_BASE_URL` localhost → `RuntimeError("OLLAMA_BASE_URL apunta a localhost")`.
4. THE PromptBuilder SHALL mantener guardrails existentes; no se requiere cambio de prompt en F2.
5. THE existing tests `tests/test_explanation_service.py` y `tests/test_llm_prompt_builder.py` SHALL seguir pasando; nuevos tests `test_llm_inconsistent_flag` y `test_ollama_prod_localhost_raises` deben pasar.

---

## Test Requirements

### Requirement 7: Cobertura de tests para F2

**User Story:** Como QA, quiero que cada tarea F2 tenga test explícito para que `pytest tests/ -v` no introduzca regresiones.

#### Acceptance Criteria

1. THE suite SHALL incluir `test_yara_whitelisted_no_dangerous` y `test_procexp64_whitelisted_is_suspicious` (T-05).
2. THE suite SHALL incluir `test_block_entropy_detects_segmented_overlay` y `test_section_coverage_anomaly` (T-06).
3. THE suite SHALL incluir `test_installer_spoof_no_discount` y preservar `test_installer_gets_discount` (T-07).
4. THE suite SHALL incluir `test_quarantine_encrypted` y `test_restore_decrypted_integrity` (T-08).
5. THE suite SHALL incluir `test_shellcode_loader_is_dangerous` (T-09).
6. THE suite SHALL incluir `test_llm_inconsistent_flag` y `test_ollama_client_prod_localhost_raises` (T-10).
7. WHEN todos los tests F2 pasan, THE suite SHALL reportar 0 nuevos FAILED vs baseline F1 (solo el fallo pre-existente de ollama debe desaparecer).
