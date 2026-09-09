# TaskV4 — Plan de Acción para Hallazgos y Limitaciones

> Plan derivado de auditoría verificada 2026-08-18 y actualizaciones 2026-08-25.
> Fuentes: `12_hallazgos.md` (H-01..H-08), `13_limitaciones.md` (L-01..L-10, R-01..R-06, CE-01..CE-05), `14_trabajo_futuro.md` (TF-01..TF-10), `07_metricas_y_resultados.md`, `05_hallazgo_multicapa.md`, `articulo_base.md`.
> Objetivo: convertir cada hallazgo/limitación/riesgo en tareas ejecutables con owner, archivos, criterios de aceptación y verificación.
> **Nota 2026-09:** documento histórico — referencias a Ollama/n8n reflejan el stack de ese momento. Stack vigente: cascada cloud Groq (`openai/gpt-oss-20b`) → Gemini (`gemini-3.5-flash-lite`) → Template offline (SDK `openai`, Ollama eliminado) y Supabase Edge Function `send-malware-alert` (n8n solo rollback). Ver [`docs/TriFallover_Groq_Gemini_Template.md`](../TriFallover_Groq_Gemini_Template.md).

---

## 0. Principios de ejecución

1. **Nada se cierra sin evidencia ejecutable** — cada tarea termina con test `pytest` verde o ejecución real logueada (como en `11_analisis_sample1.md`).
2. **Fix P0/P1 antes de feature nueva** — no integrar BehavioralShield ni SHAP hasta corregir n8n, JWT y estado `UNKNOWN`.
3. **No tocar `2381 dims` ni `scaler.pkl`** — contrato duro; cualquier cambio en extractor/modelo requiere actualizar simultáneamente `models/scaler.pkl` + `models/best_model.onnx` + tests de dimensiones.
4. **Fail-secure por defecto** — ante falta de config (Supabase/Ollama/n8n) el sistema debe degradar con `401/503` y fallback, nunca `500` ni silencio.

---

## 1. Mapa de trazabilidad — Hallazgo/Limitación → Tarea

| Origen | Descripción corta | Tarea | Fase |
|--------|-------------------|-------|------|
| H-05, L-07, TF-10/B-01, R-? | n8n silencio en DANGEROUS+BENIGN | **T-01** Fix n8n por `operational_status` | F1 P0 |
| H-06, L-08, TF-10/B-02 | JWT expirado → 500 | **T-02** Fix auth 401 fail-secure | F1 P0 |
| H-03, L-06, H-08? | `operational_status=UNKNOWN` | **T-03** Eliminar estado UNKNOWN | F1 P0 |
| L-10 | Sin timeout en extractor | **T-04** Timeout extractor | F1 P1 |
| H-03, L-06, R-04, CE-? | YARA FP Keylogger_Generic | **T-05** Whitelisting YARA + tuning | F2 P1 |
| H-08, L-09, R-01, CE-01/02 | Muestreo 50.15% en >10MB | **T-06** Entropía por bloques + muestreo | F2 P1 |
| R-02, CE-02 | Evasión instalador falso | **T-07** Endurecer descuento instalador | F2 P1 |
| R-06 | Cuarentena sin cifrado | **T-08** Cifrado cuarentena | F2 P1 |
| R-03, CE-03 | Adversarial features / sin imports | **T-09** Hardening ML/feature hashing | F2 P2 |
| R-05, L-05? | Ollama dependencia narrativa | **T-10** Validación y ranking de explicación LLM | F2 P2 |
| H-04, L-02, TF-01 | BehavioralShield no integrado | **T-11** Integrar BehavioralShield Fase 8 | F3 P2 |
| L-04, TF-09 | Sin SHAP/LIME | **T-12** SHAP sobre ONNX | F3 P2 |
| H-02, L-01, L-05/L-05a, TF-05 | Sin corpus real + test sintético incompatible | **T-13** Corpus de evaluación real | F4 P2 |
| H-01, H-08 | Hallazgo n=1 sin significancia | **T-14** Corpus overlay N≥100 + benchmark ML vs híbrido | F4 P2 |
| TF-02..TF-04, TF-06..TF-08 | Deuda de features futuras | **T-15** Backlog post-V4 (EDR/Sandbox/ELF/YARA-gen) | F5 P3 |

---

## 2. Roadmap por fases

```
F1 — Estabilización (Semana 1-2)  : T-01, T-02, T-03, T-04   ← sin esto no hay V4 shippable
F2 — Hardening heurístico (Semana 3-5): T-05, T-06, T-07, T-08, T-09, T-10
F3 — Integración profunda (Semana 6-9): T-11, T-12
F4 — Validación científica (Semana 4-12 en paralelo): T-13, T-14  ← habilita artículo revisable
F5 — Backlog quirúrgico (post-V4): T-15
```

Dependencias críticas: `T-01` y `T-03` comparten `core/heuristics/` + `core/integrations/n8n_client.py`; hacer juntos. `T-14` depende de `T-13` (corpus). `T-11` depende de `T-04` (timeout) para no colgar el pipeline.

---

## 3. Tareas F1 — Estabilización (P0/P1)

### T-01 — n8n debe alertar por `operational_status=DANGEROUS` aunque `label=BENIGN` [P0]

- **Origen:** H-05, L-07, B-01
- **Problema:** `samples/sample1.exe` (ML=0.0 BENIGN, operational_status=DANGEROUS, risk=105 CRITICAL) no dispara webhook. Toda la tesis multicapa queda muda.
- **Archivos:** `core/integrations/n8n_client.py`, `backend/app/services/scan_service.py`, `backend/app/integrations/` (si existe duplicado), `tests/test_n8n_client.py`, `tests/properties/test_n8n_properties.py`
- **Acción:**
  1. Cambiar condición de envío de `label == "malicious"` a `operational_status in (DANGEROUS, SUSPICIOUS)` OR `label == "malicious"` — parametrizable por env `N8N_ALERT_ON_STATUS=DANGEROUS,SUSPICIOUS`.
  2. Mantener compatibilidad: flag `N8N_ALERT_ON_LABEL_ONLY=false` por defecto.
  3. Actualizar `test_send_scan_result_skips_benign` — ahora debe esperar envío si status=DANGEROUS; añadir `test_send_scan_result_sends_dangerous_benign_label`.
  4. Propiedad Hypothesis: `test_prop16_non_alert_always_skip` debe reescribirse a `non_critical_always_skip`.
- **Criterios de aceptación:**
  - `sample1.exe` escaneado vía `POST /scan/upload-explain` genera webhook en modo test (verificado con mock server).
  - Tests n8n existentes adaptados pasan; nuevo test `DANGEROUS+BENIGN → send` pasa.
- **Verificación:** `pytest tests/test_n8n_client.py tests/properties/test_n8n_properties.py -v`
- **Riesgo si no se hace:** el hallazgo principal no es accionable en SOC.

### T-02 — JWT expirado debe retornar 401, no 500 [P0-P1]

- **Origen:** H-06, L-08, B-02, `10_pruebas_integracion.md` (TestExpiredJWT FAILED)
- **Archivos:** `backend/app/api/dependencies/auth.py`, `backend/app/integrations/supabase_client.py`, `tests/security/test_backend_security.py`
- **Acción:**
  1. En `auth.py`: capturar `ExpiredSignatureError` / `InvalidTokenError` y `NoSupabaseConfig` antes de cualquier `raise` no controlado; retornar `HTTPException(401, "token expired/invalid")`.
  2. Cuando `SUPABASE_URL`/`SUPABASE_JWT_SECRET` no están configurados, el modo debe ser `fail-secure` (401) no 500 con log `"Ni SUPABASE_URL ni SUPABASE_JWT_SECRET configurados"`.
  3. No loguear secrets (ya cubierto por `test_secrets_masked`).
- **Criterios:** `TestExpiredJWT::test_expired_token_rejected` pasa (401). Ningún path de auth produce 500.
- **Verificación:** `pytest tests/security/test_backend_security.py::TestExpiredJWT -v`

### T-03 — Eliminar `operational_status=UNKNOWN` [P0-P1]

- **Origen:** H-03, B-03, `02_arquitectura_general.md` (YARA early exit sin Risk)
- **Archivos:** `core/engine.py`, `core/heuristics/*`, `backend/app/schemas/dto.py`, `tests/unit/test_engine.py`, `07_metricas_y_resultados.md` (tabla procexp64)
- **Acción:**
  1. Definir invariante: `operational_status ∈ {CLEAN, SUSPICIOUS, DANGEROUS}` — nunca `UNKNOWN`.
  2. Caso `procexp64.exe` (YARA match + Risk sin triggers): debe mapear a `SUSPICIOUS` o `DANGEROUS` según política YARA (YARA hit = DANGEROUS por diseño en `02_arquitectura_general.md`), no UNKNOWN.
  3. Añadir test `test_yara_match_never_unknown`.
- **Criterios:** ningún scan real produce UNKNOWN; `pytest tests/unit/test_engine.py -k behavioral` + scan manual `procexp64.exe` verifica DANGEROUS.
- **Verificación:** `python -c "from core.engine import ShadowNetEngine; print(ShadowNetEngine().scan_file('samples/procexp64.exe').operational_status)"` ≠ UNKNOWN

### T-04 — Timeout configurable para extractor [P1]

- **Origen:** L-10
- **Archivos:** `extractors/extractor.py`, `core/engine.py`, `configs/*`, `backend/app/config.py`, `tests/test_extractors.py`
- **Acción:** envolver `extract_features()` en `concurrent.futures.ThreadPoolExecutor` con `EXTRACTOR_TIMEOUT_SECONDS` (default 15s, env configurable). On timeout → fallback `SUSPICIOUS` + `degradation_reason=extractor_timeout` + continuar pipeline (tolerancia a fallos ya existe: `test_phase_failure_continues`).
- **Criterios:** archivo con muchas secciones/strings no cuelga el pipeline; test `test_extractor_timeout_fallback` pasa.
- **Verificación:** `pytest tests/test_extractors.py -v` + benchmark con archivo sintético grande.

---

## 4. Tareas F2 — Hardening heurístico

### T-05 — Whitelisting YARA + tuning FPR [P1]

- **Origen:** H-03, L-06, `08_comparacion_ml_vs_hibrido.md` (FP YARA)
- **Archivos:** `security/yara_scanner.py`, `security/rules/*`, `configs/whitelist.json` (nuevo), `core/heuristics/*`, `tests/test_extractors.py` (packer)
- **Acción:**
  1. Crear `configs/whitelist.json` con hashes SHA-256 de software conocido-benigno (Sysinternals, debuggers). YARA hit + hash en whitelist → degradar a `SUSPICIOUS` con `whitelisted=true`, no `DANGEROUS`.
  2. Revisar regla `Keylogger_Generic` — añadir condición de exclusión para `procexp64.exe` (imports específicos + CompanyName Microsoft).
  3. Añadir métrica FPR YARA en `07_metricas_y_resultados.md` una vez exista corpus benigno (depende T-13).
- **Criterios:** `procexp64.exe` ya no produce `MALWARE` puro; test `test_yara_whitelisted_no_dangerous` pasa; FPR medido sobre corpus benigno <5% para reglas genéricas.
- **Verificación:** `pytest tests/unit/test_engine.py::TestEngineYARA -v` + scan manual procexp64.

### T-06 — Entropía por bloques + muestreo distribuido [P1]

- **Origen:** H-08, L-09, R-01, CE-01, CE-02, `05_hallazgo_multicapa.md` (limitación n=1)
- **Archivos:** `core/overlay/analyzer.py`, `extractors/extractor.py` (PE_FASTLOAD), `core/heuristics/*`, `tests/test_overlay_heuristics.py`
- **Acción:**
  1. Overlay: calcular entropía por bloques de 64KB (no solo global) + reportar `max_block_entropy`, `high_entropy_block_ratio`. Mitiga CE-01 (overlay baja entropía promedio con segmentos cifrados).
  2. Extractor PE_FASTLOAD: documentar y testear que patrón CE-02 (secciones extras para reducir overlay_ratio) es detectado vía `virtual/raw size mismatch` + `anomalous_sections`.
  3. Añadir indicador Risk: `block_entropy_anomaly=True` si >30% bloques >7.2.
- **Criterios:** overlay segmentado sintético (intercalado cifrado/limpio) es detectado; test `test_block_entropy_detects_segmented_overlay` pasa.
- **Verificación:** `pytest tests/test_overlay_heuristics.py -v`

### T-07 — Endurecer descuento de instalador [P1]

- **Origen:** R-02, CE-02, `test_installer_gets_discount`
- **Archivos:** `core/overlay/analyzer.py` (is_known_installer), `core/heuristics/*`, `tests/test_overlay_heuristics.py`
- **Acción:** el descuento NSIS/InnoSetup solo aplica si (a) magic bytes + (b) estructura de secciones de instalador + (c) overlay_ratio <90%. Si overlay_ratio >93% aunque haya magic bytes, no hay descuento — marcar `installer_spoof_suspected=True`.
- **Criterios:** binario sintético con magic NSIS + overlay 98% sigue siendo CRITICAL; test `test_installer_spoof_no_discount` pasa.

### T-08 — Cifrado de cuarentena [P1]

- **Origen:** R-06, `13_limitaciones.md`
- **Archivos:** `backend/app/api/routes/quarantine.py`, `backend/app/services/*quarantine*`, `utils/*`, `tests/unit/test_quarantine.py`
- **Acción:** cifrar archivos en `~/.shadownet/quarantine/` con `cryptography.fernet` (clave derivada de `QUARANTINE_KEY` env o generada y almacenada con permisos 600). Mantener SHA-256 en metadata para `test_restore_integrity`.
- **Criterios:** archivo en cuarentena no es legible sin clave; `quarantine → restore` roundtrip preserva bytes y SHA-256.
- **Verificación:** `pytest tests/unit/test_quarantine.py -v` + inspección `~/.shadownet/quarantine/` no contiene bytes planos.

### T-09 — Hardening ML: colisiones feature hashing + sin imports [P2]

- **Origen:** R-03, R-04, CE-03, `test_no_imports_raises_score`
- **Archivos:** `extractors/*` (imports 1280 buckets), `core/heuristics/*`, `tests/test_extractors.py`
- **Acción:**
  1. Documentar colisión 1280 buckets como limitación conocida en `13_limitaciones.md`; evaluar pasar a 2048 buckets solo si se reentrena y regenera `scaler.pkl` + `best_model.onnx` (no hacer sin T-13).
  2. Reforzar `CE-03` (loader sin imports): Risk ya eleva score (`test_no_imports_raises_score` PASS) — añadir correlación con `executable_sections==1 && num_imports==0 → risk +=` y test `test_shellcode_loader_is_dangerous`.
  3. Añadir nota R-03 en docs: artefactos ONNX/scaler deben considerarse secreto; si se exponen, el modelo es atacable.
- **Criterios:** loader sintético sin imports es DANGEROUS; docs actualizados.
- **Verificación:** tests overlay/heuristics + revisión docs.

### T-10 — Validación de explicación LLM [P2]

- **Origen:** R-05, `06_xai_explicabilidad.md`, `15_ollama.md`
- **Archivos:** `core/llm/prompt_builder.py`, `core/llm/explanation_service.py`, `core/llm/ollama_client.py`, `backend/app/services/llm_service.py`, `tests/test_explanation_service.py`
- **Acción:**
  1. Añadir validador post-LLM: `threat_level` debe ser consistente con `risk_level` (si Risk=CRITICAL, LLM no puede decir `none` sin marcar `inconsistent=true`).
  2. Añadir ranking de confianza de la explicación (no del binario): `llm_confidence` basado en si la respuesta cita indicadores reales del `ScanResult`.
  3. Fix `test_ollama_client_prod_localhost_raises` (FAILED en `07_metricas`) — validar que `OLLAMA_BASE_URL` con `localhost` en prod lanza `RuntimeError`.
- **Criterios:** LLM que contradice Risk es marcado inconsistente; test prod_localhost pasa.
- **Verificación:** `pytest tests/test_ollama_client.py tests/test_explanation_service.py -v`

---

## 5. Tareas F3 — Integración profunda

### T-11 — Integrar BehavioralShield como Fase 8 [P2]

- **Origen:** H-04, L-02, TF-01, `04_sistema_hibrido_multicapa.md` (NO integrado)
- **Archivos:** `core/dynamic/process_monitor.py`, `core/engine.py` (scan_file), `backend/app/schemas/dto.py` (ScanResult), `tests/unit/test_engine.py` (nuevo)
- **Acción:**
  1. Conectar `BehavioralShield` como Fase 8 opcional: `engine.scan_file(path, enable_behavioral=False)` por defecto OFF (no romper CI).
  2. Cuando `enable_behavioral=True`: monitorear PID si el archivo está en ejecución; detectar inyección (handle remoto), persistencia (Run key), networking anómalo.
  3. Añadir `behavioral_analysis` al `ScanResult` con misma estructura que `il_behavioral` (source/value/location/confidence).
  4. Risk Engine consume `behavioral_analysis` si existe.
  5. Añadir timeout `BEHAVIORAL_TIMEOUT` (ya en `test_behavioral_timeout_default`).
- **Criterios:** `scan_file(enable_behavioral=True)` incluye `behavioral_analysis`; sin flag, comportamiento idéntico a V3. Tests nuevos pasan; `test_phase_failure_continues` sigue pasando si psutil falla.
- **Verificación:** `pytest tests/unit/test_engine.py -v` + ejecución manual con proceso de prueba.
- **Dependencia:** T-04 (timeout) para no colgar.

### T-12 — SHAP / interpretabilidad ML [P2]

- **Origen:** L-04, TF-09, `06_xai_explicabilidad.md`
- **Archivos:** `core/explain/*` (nuevo), `models/inference.py`, `backend/app/schemas/dto.py`, `tests/` (nuevo)
- **Acción:**
  1. Implementar SHAP KernelExplainer sobre `onnxruntime` (no PyTorch en prod — `requirements/base.in` no debe incluir `torch`).
  2. Exponer `GET /explain/shap?file_path=...` que retorna top-20 features con mayor contribución.
  3. Integrar SHAP en `ScanResult.llm_context` para que Ollama cite features reales.
  4. Benchmark: SHAP no debe superar `LLM_TIMEOUT` (30s) — muestrear background de 100 muestras.
- **Criterios:** endpoint retorna SHAP values; test `test_shap_top_features` pasa; docs `06_xai` actualizados.
- **Verificación:** `pytest tests/test_shap* -v` (nuevo) + `curl /explain/shap`.

---

## 6. Tareas F4 — Validación científica (paralela, bloquea artículo)

### T-13 — Corpus de evaluación real con ground truth externo [P2 — crítico para rigor]

- **Origen:** H-02, L-01, L-05/L-05a, TF-05, `07_metricas_y_resultados.md` (test sintético incompatible)
- **Archivos:** `data/test_set/` (reemplazar o complementar), `docs/academico/07_metricas_y_resultados.md`, `evaluation/*`, `Model_Collab/` (referencia)
- **Acción:**
  1. Construir `data/eval_real/` con ≥1000 malware + ≥1000 benignos con ground truth ≥5 motores AV (VirusTotal) o sandbox. No incluir en git si hay riesgo legal — documentar proceso de adquisición en `07_metricas`.
  2. Recalcular compatibilidad con `scaler.pkl` — verificar `mean≈0, std≈1` post-scaling sobre corpus real (a diferencia de `mean=21.73, std=112.1` del sintético).
  3. Calcular y reportar: Accuracy, Precision, Recall, F1, AUC-ROC, FPR@TPR=90%, TPR@FPR=1% para solo-ML y para híbrido.
  4. Comparar métricas declaradas `07_metricas` (accuracy 0.9815 sobre 765K híbrido) vs métricas de campo — documentar gap de generalización (padding de ceros 33→2381).
  5. Marcar `data/test_set/X_test.npy` como `SINTETICO — no usar para métricas` en `figures/fig7*`.
- **Criterios:** `07_metricas_y_resultados.md` contiene tabla con métricas de campo verificables; `pytest tests/integration/test_pipeline_e2e.py::test_accuracy_above_threshold` pasa sobre `eval_real` o es reemplazado por test con umbral realista.
- **Verificación:** `python evaluation/evaluate_real_corpus.py --corpus data/eval_real/` produce `metrics.json` con AUC>0.90 esperado.
- **Nota:** sin T-13, el artículo no puede reportar métricas de campo — es deuda que invalida claims de `articulo_base.md` §6.4.

### T-14 — Corpus overlay N≥100 + benchmark ML vs híbrido [P2]

- **Origen:** H-01, `05_hallazgo_multicapa.md` (limitación n=1), `11_analisis_sample1.md`
- **Archivos:** `samples/overlay_corpus/` (nuevo), `tests/test_overlay_heuristics.py`, `docs/academico/05_hallazgo_multicapa.md`, `07_metricas_y_resultados.md`, `08_comparacion_ml_vs_hibrido.md`
- **Acción:**
  1. Recolectar N≥100 PE con overlay payload (droppers, packers custom) — confirmar con VirusTotal que son maliciosos.
  2. Medir FNR solo-ML vs FNR híbrido sobre ese corpus. Hipótesis: FNR híbrido < FNR ML con p<0.05 (McNemar).
  3. Verificar que `sample1.exe` no es outlier — reportar distribución de `overlay_ratio` y `overlay_entropy` del corpus.
  4. Publicar `figures/fig_overlay_benchmark.png` con barras ML vs híbrido.
- **Criterios:** tabla ML vs híbrido con N, FNR, p-value; hallazgo pasa de n=1 a n≥100.
- **Verificación:** `python evaluation/benchmark_overlay.py --corpus samples/overlay_corpus/`

---

## 7. T-15 — Backlog post-V4 [P3]

No bloquea V4; priorizar después de F1-F4:

| ID | TF origen | Descripción | Nota |
|----|-----------|-------------|------|
| T-15a | TF-02 | Memory forensics (Volatility) — `engine.scan_memory_region(pid, addr, size)` | Detecta fileless |
| T-15b | TF-03 | EDR loop: BehavioralShield + auto-terminate/quarantine + dashboard | Requiere T-11 |
| T-15c | TF-04 | Sandbox (Cuckoo/VM) — correlacionar sandbox vs estático | Valida IL Behavioral |
| T-15d | TF-06 | ELF support — extractor ELF + YARA Linux | Nuevo `extractors/elf/` |
| T-15e | TF-08 | Generación automática YARA — clustering + validación FPR | Requiere T-13 |
| T-15f | TF-07 | Windows Service hardening | `deploy/shadownet.service` |
| T-15g | — | EICAR YARA — añadir firma EICAR estándar | Fix trivial, incluir en T-05 |

---

## 8. Criterios de cierre de V4

V4 se considera cerrada cuando:

- [ ] T-01, T-02, T-03, T-04 mergeados y `pytest tests/ -v` ≥ 155/158 (sin nuevos FAILED por regresión). `TestExpiredJWT` y `ollama_prod_localhost` ya no fallan.
- [ ] `sample1.exe` genera alerta n8n y `procexp64.exe` no produce UNKNOWN.
- [ ] T-05..T-10 mergeados o con issue abierto con owner y fecha.
- [ ] T-13 y T-14 con al menos corpus piloto N≥100 y métricas preliminares en `07_metricas_y_resultados.md`.
- [ ] `13_limitaciones.md` actualizado marcando cada L/R/CE como `mitigado / en progreso / pendiente` con referencia a PR.
- [ ] `verify_readiness.py` pasa y `pytest --cov` reportado (pendiente en `09_pruebas_unitarias.md`).

---

## 9. Riesgos si no se ejecuta el plan

1. **Artículo rechazado** — sin T-13/T-14, las métricas son sintéticas (H-02) y el hallazgo es n=1 (H-01).
2. **SOC ciego** — sin T-01, el caso DANGEROUS más crítico no alerta.
3. **Falsos positivos operativos** — sin T-05, despliegue en endpoint con Sysinternals genera ruido y desconfianza.
4. **Evasión trivial** — sin T-06/T-07, overlay segmentado o instalador spoofeado evade Risk Engine (R-01/R-02).
5. **Deuda de seguridad** — sin T-02/T-08, JWT 500 y cuarentena sin cifrado son hallazgos de auditoría externa.

---

## 10. Referencias cruzadas

- Hallazgos: `12_hallazgos.md` H-01..H-08
- Limitaciones/riesgos/evasión: `13_limitaciones.md` L-01..L-10, R-01..R-06, CE-01..CE-05
- Trabajo futuro: `14_trabajo_futuro.md` TF-01..TF-10
- Métricas: `07_metricas_y_resultados.md` (incl. métricas recuperadas 07-25 de `Model_Collab/ShadowNet Defender - v3.0.ipynb`)
- Arquitectura: `02_arquitectura_general.md`, `04_sistema_hibrido_multicapa.md`
- Pruebas: `09_pruebas_unitarias.md`, `10_pruebas_integracion.md`
- XAI/LLM: `06_xai_explicabilidad.md`, `15_ollama.md`
- Artículo base: `articulo_base.md` §8-10
