# Tasks — ShadowNet Defender F3 Integración Profunda

## Task List

- [ ] 1 T-11: Integrar BehavioralShield como Fase 8 opcional (enable_behavioral=False)
  - [ ] 1.1 Modificar `core/engine.py` — `scan_file(file_path, *, enable_behavioral=False)` delega a `_scan_file_internal(file_path, enable_behavioral)` dentro del watchdog `ANALYSIS_TIMEOUT_SECONDS`
  - [ ] 1.2 Modificar `_scan_file_internal` — añadir param `enable_behavioral`, inicializar `behavioral_analysis=None`, ejecutar `self._run_behavioral_phase()` solo si `enable_behavioral==True`
  - [ ] 1.3 Verificar `_run_behavioral_phase()` y `_resolve_pid()` ya existentes respetan `BEHAVIORAL_SHIELD_TIMEOUT_SECONDS=2s` y capturan `psutil.AccessDenied/NoSuchProcess` sin propagar
  - [ ] 1.4 Modificar `backend/app/services/scan_service.py` — `scan_single_file(file_path, *, enable_behavioral=False)` pasa flag a `engine.scan_file()`
  - [ ] 1.5 Verificar `configs/settings.py` contiene `BEHAVIORAL_SHIELD_TIMEOUT_SECONDS` y `backend/app/schemas/dto.py` contiene `behavioral_analysis: Optional[Dict]` (ya existen desde audit-improvements)
  - [ ] 1.6 Añadir `test_behavioral_disabled_is_noop` en `tests/unit/test_engine.py` — `scan_file(enable_behavioral=False)` → `BEHAVIORAL ∉ detection_phases` y `behavioral_analysis is None`
  - [ ] 1.7 Verificar `test_behavioral_elevation_dangerous` y `test_behavioral_elevation_suspicious` ya existentes siguen PASSED con flag activo
  - [ ] 1.8 Añadir `test_behavioral_timeout_graceful` — mock `analyze_process` que duerme >2s → `behavioral_analysis is None` sin excepción
  - [ ] 1.9 Ejecutar `pytest tests/unit/test_engine.py -v` y confirmar PASSED

- [ ] 2 T-12: SHAP sobre ONNX sin torch en prod
  - [ ] 2.1 Crear `core/explain/__init__.py` y `core/explain/shap_explainer.py` — clase `ShapExplainer` con `onnxruntime` + `numpy` + `joblib`, carga `models/best_model.onnx` + `models/scaler.pkl`, background 100 muestras, `explain(features, top_k=20)` con timeout 30s
  - [ ] 2.2 Implementar `_load_background()`, `_predict_fn()`, `_load_feature_names()` (2381 nombres) y `explain()` con `shap.KernelExplainer` (nsamples=100) o fallback `shap_not_installed`
  - [ ] 2.3 Crear `backend/app/api/routes/explain.py` — `GET /explain/shap?file_path=&top_k=20` valida traversal/existe/PE, llama a `PEFeatureExtractor.extract()` + `ShapExplainer.explain()`, retorna `{top_features, base_value, model_score}`; registrar router en `backend/app/main.py`
  - [ ] 2.4 Verificar `requirements/base.in` NO contiene `torch`; añadir `shap>=0.44.0` a `requirements/ml.in` si no existe
  - [ ] 2.5 Actualizar `docs/academico/06_xai_explicabilidad.md` — documentar Nivel 3 SHAP con ejemplo JSON y limitación de no-determinismo/timeout
  - [ ] 2.6 Añadir `test_shap_top_features` en `tests/test_shap.py` — `explain()` sobre vector sintético retorna 20 features con `shap_value` finito y `feature_name` no vacío
  - [ ] 2.7 Añadir `test_explain_shap_endpoint` — `GET /explain/shap` retorna 200 con `top_features` para PE mock y 400 para no-PE/path traversal
  - [ ] 2.8 Añadir `test_shap_no_torch_in_base` — assert `"torch" not in open("requirements/base.in").read().lower()`
  - [ ] 2.9 Ejecutar `pytest tests/test_shap* -v` y confirmar PASSED (o skipped si `shap` no instalado)

- [ ] 3 Verificación final F3
  - [ ] 3.1 Ejecutar `pytest tests/ -v` y verificar 0 nuevos FAILED vs baseline F2
  - [ ] 3.2 Verificar `grep -i torch requirements/base.in` vacío
  - [ ] 3.3 Verificar `curl` o `TestClient` a `GET /explain/shap?file_path=samples/sample1.exe` retorna 200 con `model_score` numérico
  - [ ] 3.4 Confirmar `scan_file(enable_behavioral=False)` sobre `samples/sample1.exe` es byte-idéntico a V3 salvo `behavioral_analysis=None`
