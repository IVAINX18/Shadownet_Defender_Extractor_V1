# Requirements Document — ShadowNet Defender F3 Integración Profunda

## Introduction

Este documento cubre la fase **F3 — Integración profunda** de ShadowNet Defender (TaskV4), compuesta por dos tareas **T-11** y **T-12** que llevan la tesis híbrida al siguiente nivel: detección dinámica y explicabilidad del modelo ML. F3 asume **F1 Estabilización y F2 Hardening completados** (invariante `operational_status`, whitelist YARA, entropía por bloques, cifrado cuarentena, validación LLM). F3 no modifica el contrato `2381 dims` ni `scaler.pkl`/`best_model.onnx` salvo para lectura SHAP.

F3 convierte dos limitaciones críticas abiertas (`13_limitaciones.md` L-02/L-04) en capacidades auditables:
- **T-11 (H-04/L-02/TF-01)**: `core/dynamic/process_monitor.py` existe pero **no estaba conectado** a `scan_file()` en V3. Ahora debe ser **Fase 8 opcional** con flag `enable_behavioral`.
- **T-12 (L-04/TF-09)**: el modelo ONNX es caja negra. Ahora debe exponer **SHAP KernelExplainer** sin PyTorch en prod y endpoint `GET /explain/shap`.

---

## Glossary

- **BehavioralShield**: `core/dynamic/process_monitor.py` — `BehavioralShield.analyze_process(pid)` + `scan_all_processes()`, usa `psutil`, timeout 2s.
- **BehaviorReport**: dataclass con `pid`, `process_name`, `risk_score ∈ [0,1]`, `is_suspicious (≥0.3)`, `suspicious_actions[]`, `scan_time_ms`.
- **SuspiciousAction**: `{description, severity ∈ [0,1], ioc_type ∈ {network,process,cpu,filesystem,injection}}`.
- **ShadowNetEngine**: `core/engine.py` — `scan_file(path, enable_behavioral=False)` orquesta pipeline YARA→UPX→ML→Overlay→DotNet→IL→Behavioral→Risk.
- **RiskEngine**: `core/heuristics/` — `HeuristicRiskEngine.assess()` produce `operational_status ∈ {CLEAN,SUSPICIOUS,DANGEROUS}`.
- **SHAP**: SHapley Additive exPlanations — KernelExplainer sobre `onnxruntime` para top-20 features.
- **ScanResult**: `backend/app/schemas/dto.py` — DTO con `behavioral_analysis: Optional[Dict]` + campos `llm_context`.
- **EXTRACTOR_TIMEOUT_SECONDS**: ya existe en `configs/settings.py` (F1 T-04) — timeout interno de `extract()`.
- **BEHAVIORAL_SHIELD_TIMEOUT_SECONDS**: `int(os.getenv("BEHAVIORAL_SHIELD_TIMEOUT_SECONDS","2"))` en `configs/settings.py` (ya existe).
- **llm_context**: campo opcional en `ScanResult` que incluye SHAP top features para que Ollama cite features reales.

---

## Requirements

### Requirement 1: Integrar BehavioralShield como Fase 8 opcional (T-11)

**User Story:** Como analista SOC, quiero que `scan_file(enable_behavioral=True)` eleve `operational_status` si el binario está en ejecución y muestra inyección/persistencia/networking anómalo, para detectar malware benigno-en-estático pero malicioso-en-ejecución (CE-05).

#### Acceptance Criteria

1. THE ShadowNetEngine SHALL exponer `scan_file(file_path, enable_behavioral=False)` donde `enable_behavioral=False` preserva comportamiento V3 idéntico (sin psutil, sin cambios en `operational_status`).
2. WHEN `enable_behavioral=True` y el archivo corresponde a un PID activo (comparación `exe` normalizado vía `psutil.process_iter`), THE Engine SHALL invocar `BehavioralShield.analyze_process(pid)` como Fase 8 en `_scan_file_internal` con timeout `BEHAVIORAL_SHIELD_TIMEOUT_SECONDS` (default 2s).
3. WHEN `BehaviorReport.risk_score >= 0.5` y `operational_status in (CLEAN,SUSPICIOUS)`, THE Engine SHALL elevar `operational_status` a `DANGEROUS` e incluir `suspicious_actions` en `behavioral_analysis`.
4. WHEN `0.3 <= risk_score < 0.5` y `operational_status == CLEAN`, THE Engine SHALL elevar a `SUSPICIOUS`.
5. IF `psutil` no está disponible o PID no encontrado o excepción en `analyze_process`, THEN THE Engine SHALL continuar sin error, `behavioral_analysis=None`, y loguear en DEBUG sin propagar excepción.
6. THE `ScanResult` DTO SHALL incluir `behavioral_analysis: Optional[Dict]` con estructura `{pid, process_name, risk_score, is_suspicious, suspicious_actions[], scan_time_ms}` o `None`.
7. THE RiskEngine SHALL consumir `behavioral_analysis` si existe (no modificar `label`/`score` ML, solo `operational_status`/`risk_level`/`risk_score`).
8. THE Fase 8 SHALL respetar `EXTRACTOR_TIMEOUT_SECONDS` y el watchdog global `ANALYSIS_TIMEOUT_SECONDS` (60s) — no debe colgar el pipeline.

### Requirement 2: SHAP sobre ONNX sin PyTorch en prod (T-12)

**User Story:** Como investigador, quiero `GET /explain/shap?file_path=...` que retorne top-20 features con mayor contribución SHAP para un binario, para auditar por qué el modelo dio score 0.91 y alimentar a Ollama con contexto real.

#### Acceptance Criteria

1. THE System SHALL implementar `core/explain/shap_explainer.py` con `ShapExplainer` que use **solo** `onnxruntime` + `numpy` + `shap` (KernelExplainer o GradientExplainer compatible ONNX) — **prohibido** `torch` en `requirements/base.in`.
2. THE `ShapExplainer` SHALL cargar `models/best_model.onnx` y `models/scaler.pkl`, muestrear background de 100 muestras (o `data/test_set` si disponible) y exponer `explain(features: np.ndarray, top_k=20) -> List[{feature_idx, feature_name, shap_value}]`.
3. THE System SHALL exponer `GET /explain/shap` en `backend/app/api/routes/explain.py` (o `analysis.py`) con query `file_path` y auth JWT opcional, que extrae features vía `PEFeatureExtractor`, llama a `ShapExplainer.explain()` y retorna JSON con `top_features`, `base_value`, `model_score`.
4. THE `ScanResult.llm_context` (o `details.llm_context`) SHALL incluir `shap_top_features` cuando `GET /explain/shap` sea consumido por `llm_service`, para que `PromptBuilder` cite features reales en el prompt Ollama.
5. THE `ShapExplainer.explain()` SHALL completar en < `LLM_TIMEOUT` (30s) para un binario PE normal; si excede, retornar `error="shap_timeout"` sin lanzar 500.
6. THE endpoint SHALL validar `file_path` contra path traversal y retornar 400 si el archivo no existe o no es PE válido, sin exponer stack trace.
7. THE docs `06_xai_explicabilidad.md` SHALL actualizarse para documentar SHAP como Nivel 3 de XAI (Forense + Narrativo + SHAP), con ejemplo de salida y limitación de no-determinismo.

### Requirement 3: No regresión y timeouts (T-11 + T-12 transversales)

**User Story:** Como DevOps, quiero que F3 no rompa CI y que ningún binario cuelgue el pipeline más allá de los timeouts configurados.

#### Acceptance Criteria

1. WHEN `enable_behavioral=False` (default), THE `scan_file()` SHALL producir resultado byte-identico a V3 para `samples/sample1.exe` y `samples/procexp64.exe` (salvo campo `behavioral_analysis=None` añadido).
2. THE test `test_phase_failure_continues` SHALL seguir PASSED si `BehavioralShield.analyze_process` lanza excepción o psutil falla.
3. THE `EXTRACTOR_TIMEOUT_SECONDS` (15s) y `BEHAVIORAL_SHIELD_TIMEOUT_SECONDS` (2s) SHALL operar como timeouts internos dentro del watchdog global `ANALYSIS_TIMEOUT_SECONDS` (60s) sin interferencia.
4. THE `requirements/base.in` SHALL NOT contener `torch`; `requirements/ml.in` o `requirements/viz.in` puede contener `shap` si se requiere.
5. THE `pytest tests/ -v` SHALL mantener ≥136 passed de F2 sin nuevos FAILED por F3.

---

## Test Requirements

### Requirement 4: Cobertura de tests para F3

**User Story:** Como QA, quiero que cada tarea F3 tenga test explícito para que `pytest` valide la nueva fase y SHAP sin depender de binarios reales maliciosos.

#### Acceptance Criteria

1. THE suite SHALL incluir `test_behavioral_disabled_is_noop` — `scan_file(enable_behavioral=False)` no añade `BEHAVIORAL` a `detection_phases` y `behavioral_analysis is None`.
2. THE suite SHALL incluir `test_behavioral_elevation_dangerous` y `test_behavioral_elevation_suspicious` — mock `BehavioralShield.risk_score 0.7→DANGEROUS`, `0.35→SUSPICIOUS`.
3. THE suite SHALL incluir `test_behavioral_timeout_graceful` — mock `analyze_process` que duerme >2s → `behavioral_analysis is None` y pipeline continúa.
4. THE suite SHALL incluir `test_shap_top_features` — `ShapExplainer.explain()` sobre vector sintético retorna 20 features con `shap_value` numérico y `feature_name` no vacío.
5. THE suite SHALL incluir `test_explain_shap_endpoint` — `GET /explain/shap?file_path=tmp_pe` retorna 200 con `top_features` y `model_score`, y 400 para no-PE.
6. THE suite SHALL incluir `test_shap_no_torch_in_base` — `requirements/base.in` no contiene `torch`.
7. WHEN todos los tests F3 pasan, THE suite SHALL reportar 0 nuevos FAILED vs baseline F2.
