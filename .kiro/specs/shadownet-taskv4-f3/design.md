# Design Document — ShadowNet Defender F3 Integración Profunda

## Overview

F3 cierra dos deudas estructurales de V3: **BehavioralShield desconectado** (`core/dynamic/process_monitor.py` existía pero `engine._scan_file_internal` nunca lo llamaba) y **modelo ONNX opaco** (L-04). F3 añade **Fase 8 dinámica opcional** y **SHAP KernelExplainer** sin `torch` en prod. Ambas features son **opt-in** (flag y endpoint) para no romper CI ni degradar latencia por defecto.

```
Pipeline F3 (8 fases, última opcional):

  [F1] YARA Scanner          ──→ DANGEROUS early exit (whitelist-aware desde F2)
  [F2] UPX Unpack            ──→ was_unpacked
  [F3] ML Extract+ONNX       ──→ label/score + EXTRACTOR_TIMEOUT (F1)
  [F4] Overlay Forensics     ──→ block_entropy (F2) + installer_spoof (F2)
  [F5] DotNet/CLR            ──→ obfuscator/dll embed
  [F6] IL Behavioral         ──→ threat_score/family
  [F7] Risk Engine           ──→ operational_status
  [F8] BehavioralShield      ──→ (opt-in) psutil analyze_process(pid) → eleva status
          │
          └── SHAP off-path: GET /explain/shap → core/explain/shap_explainer.py → llm_context
```

T-11 depende de T-04 (timeout ya existe); T-12 es independiente y puede ir en paralelo.

---

## Architecture

### Componentes afectados

```
core/engine.py                         ← T-11: scan_file(enable_behavioral=False) + _run_behavioral_phase()
core/dynamic/process_monitor.py        ← T-11: ya existe, sin cambios salvo contrato
configs/settings.py                    ← T-11: BEHAVIORAL_SHIELD_TIMEOUT_SECONDS ya existe (verificar)
backend/app/schemas/dto.py             ← T-11: behavioral_analysis: Optional[Dict] (ya existe desde audit-improvements)
backend/app/services/scan_service.py   ← T-11: scan_single_file(enable_behavioral=False) → engine
core/explain/shap_explainer.py         ← T-12: nuevo, ShapExplainer (onnxruntime + numpy)
core/explain/__init__.py               ← T-12: re-export
backend/app/api/routes/explain.py      ← T-12: nuevo, GET /explain/shap  (o analysis.py)
backend/app/api/routes/analysis.py     ← T-12: alternativa si explain.py no existe
requirements/base.in                   ← T-12: NO torch
requirements/ml.in o viz.in            ← T-12: shap
docs/academico/06_xai_explicabilidad.md← T-12: Nivel 3 SHAP
tests/unit/test_engine.py              ← T-11: 3 tests nuevos
tests/test_shap.py                     ← T-12: 3 tests nuevos
```

### Diagrama de flujo — T-11 enable_behavioral

```
scan_file(path, enable_behavioral=False)
  → _scan_file_internal(path, enable_behavioral)
      F1..F7 (siempre)
      if enable_behavioral and behavioral_shield is not None and label != NOT_PE:
          pid = _resolve_pid(path)               # psutil.process_iter exe normalizado
          if pid is not None:
              with ThreadPoolExecutor(1) as ex:
                  future = ex.submit(shield.analyze_process, pid)
                  report = future.result(timeout=BEHAVIORAL_SHIELD_TIMEOUT_SECONDS)  # 2s
                  behavioral_analysis = {pid, process_name, risk_score, is_suspicious, actions, scan_time_ms}
                  if risk_score >= 0.5 and operational_status in (CLEAN,SUSPICIOUS): DANGEROUS
                  elif risk_score >= 0.3 and operational_status == CLEAN: SUSPICIOUS
          else: behavioral_analysis = None
      else: behavioral_analysis = None
```

### Diagrama de flujo — T-12 SHAP

```
GET /explain/shap?file_path=/tmp/sample.exe
  → valida file_path (path traversal, existe, PE)
  → PEFeatureExtractor.extract(path)           # 2381 dims, respeta EXTRACTOR_TIMEOUT
  → scaler.transform(features)                 # StandardScaler
  → ShapExplainer.explain(scaled_features, top_k=20)
      background = 100 muestras (X_test.npy o sintético)
      explainer = shap.KernelExplainer(onnx_predict_fn, background)
      shap_values = explainer.shap_values(scaled_features, nsamples=100)
      top_features = sorted(zip(feature_names, shap_values), key=abs)[:20]
  → {top_features, base_value, model_score, feature_names}
  → (futuro) llm_service inyecta top_features en llm_context para PromptBuilder
```

---

## Detailed Design

### T-11 — BehavioralShield Fase 8 (enable_behavioral=False por defecto)

**Estado actual verificado:**

- `core/dynamic/process_monitor.py:64` `BehavioralShield` ya implementado con `analyze_process(pid)` y `scan_all_processes()`.
- `core/engine.py:820` ya tiene `_resolve_pid()` y `_run_behavioral_phase()` integrados desde audit-improvements, pero `scan_file()` no expone flag `enable_behavioral` — se ejecuta **siempre** si `_behavioral_shield is not None` y `label != NOT_PE`. **F3 debe hacerlo opt-in** para no romper CI.

**Cambios en `core/engine.py`:**

```python
# 1. scan_file con flag opt-in
def scan_file(self, file_path: Union[str, Path], *, enable_behavioral: bool = False) -> Dict[str, Any]:
    # watchdog existente...
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(self._scan_file_internal, file_path, enable_behavioral)
        return future.result(timeout=ANALYSIS_TIMEOUT_SECONDS)

# 2. _scan_file_internal con flag
def _scan_file_internal(self, file_path: Path, enable_behavioral: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        # ... campos existentes, operational_status ya es SUSPICIOUS por F1
        "behavioral_analysis": None,
    }
    # F1..F7 sin cambios...
    # F8 — solo si flag activo
    if enable_behavioral:
        self._run_behavioral_phase(file_path, result)
    else:
        result["behavioral_analysis"] = None

# 3. _run_behavioral_phase ya existe — verificar que respeta timeout 2s y captura psutil.AccessDenied
# No cambiar lógica 0.5→DANGEROUS / 0.3→SUSPICIOUS (ya correcta).

# 4. _resolve_pid ya existe — normaliza exe con Path.resolve().lower()
```

**Cambios en `backend/app/services/scan_service.py`:**

```python
def scan_single_file(file_path: Path, *, scan_type: ScanType = ScanType.SINGLE, enable_behavioral: bool = False) -> ScanResult:
    raw_result = engine.scan_file(file_path, enable_behavioral=enable_behavioral)
    # ... resto idéntico, behavioral_analysis ya viene en raw_result
```

**Cambios en `backend/app/api/routes/scan.py` (opcional, si existe query param):**

```python
@router.post("/scan/file")
def scan_file(file: UploadFile, enable_behavioral: bool = Query(False), user=Depends(get_current_user)):
    # ... guardar temp file
    result = scan_single_file(tmp_path, enable_behavioral=enable_behavioral)
```

**No cambiar:** `configs/settings.py` ya tiene `BEHAVIORAL_SHIELD_TIMEOUT_SECONDS=2` — verificar. `backend/app/schemas/dto.py` ya tiene `behavioral_analysis: Optional[Dict]` — verificar.

**Tests T-11:**

```python
def test_behavioral_disabled_is_noop(tmp_path):
    with patch("core.engine.ShadowNetEngine.__init__", return_value=None):
        engine = ShadowNetEngine.__new__(ShadowNetEngine)
        engine._behavioral_shield = MagicMock()
        engine._resolve_pid = MagicMock(return_value=1234)
        result = {"detection_phases": [], "label": "BENIGN", "operational_status": "CLEAN", "behavioral_analysis": None, "details": {}}
        engine._run_behavioral_phase(tmp_path/"test.exe", result)  # path con flag False no debe llamarse
        # Versión con enable_behavioral=False: _run_behavioral_phase no se invoca desde _scan_file_internal
        assert "BEHAVIORAL" not in result["detection_phases"]

def test_behavioral_timeout_graceful(tmp_path):
    engine._behavioral_shield.analyze_process = lambda pid: time.sleep(5) or BehaviorReport(...)
    # con timeout 2s → behavioral_analysis is None y no propaga
```

### T-12 — SHAP KernelExplainer sin torch

**Nuevo módulo:** `core/explain/shap_explainer.py`

```python
from __future__ import annotations
import numpy as np
from pathlib import Path
from typing import List, Dict, Any
import joblib
import onnxruntime as ort

class ShapExplainer:
    """SHAP sobre ONNX Runtime — sin torch."""
    def __init__(self, model_path: Path = None, scaler_path: Path = None, background_n: int = 100):
        from configs.settings import MODEL_PATH, SCALER_PATH
        self.model_path = model_path or MODEL_PATH
        self.scaler_path = scaler_path or SCALER_PATH
        self.scaler = joblib.load(self.scaler_path)
        self.session = ort.InferenceSession(str(self.model_path), providers=["CPUExecutionProvider"])
        self.input_name = self.session.get_inputs()[0].name
        self.background = self._load_background(background_n)
        self.feature_names = self._load_feature_names()  # 2381 nombres o idx

    def _load_background(self, n: int) -> np.ndarray:
        # Intenta data/test_set/X_test.npy (1000,2381) — si existe, sample 100
        # Si no, genera background sintético (zeros + gaussian) — determinista
        ...

    def _predict_fn(self, X: np.ndarray) -> np.ndarray:
        # X ya escalado — inferencia ONNX batch
        return self.session.run(None, {self.input_name: X.astype(np.float32)})[0].ravel()

    def explain(self, features: np.ndarray, top_k: int = 20) -> Dict[str, Any]:
        # features.shape == (2381,) o (1,2381)
        # Usa shap.KernelExplainer con background y predict_fn
        # nsamples=100 para <30s
        # Retorna {top_features: [{feature_idx, feature_name, shap_value}], base_value, model_score}
```

**Pseudocódigo de `explain` con timeout:**

```python
def explain(self, features: np.ndarray, top_k: int = 20) -> Dict[str, Any]:
    import concurrent.futures, time, shap
    scaled = self.scaler.transform(features.reshape(1, -1))  # (1,2381)
    # fallback si shap no instalado
    try:
        import shap
    except ImportError:
        return {"error": "shap_not_installed", "top_features": []}
    def _run():
        explainer = shap.KernelExplainer(self._predict_fn, self.background)
        shap_values = explainer.shap_values(scaled, nsamples=100)
        base = float(explainer.expected_value) if hasattr(explainer, "expected_value") else 0.0
        vals = shap_values[0] if isinstance(shap_values, list) else shap_values.ravel()
        idx = np.argsort(np.abs(vals))[::-1][:top_k]
        top = [{"feature_idx": int(i), "feature_name": self.feature_names[i], "shap_value": float(vals[i])} for i in idx]
        score = float(self._predict_fn(scaled)[0])
        return {"top_features": top, "base_value": base, "model_score": score}
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(_run)
        try:
            return future.result(timeout=30)  # LLM_TIMEOUT
        except concurrent.futures.TimeoutError:
            return {"error": "shap_timeout", "top_features": []}
```

**Nuevo endpoint:** `backend/app/api/routes/explain.py`

```python
from fastapi import APIRouter, Query, HTTPException, Depends
from pathlib import Path
from extractors.extractor import PEFeatureExtractor
from core.explain.shap_explainer import ShapExplainer

router = APIRouter(prefix="/explain", tags=["explain"])
_extractor = PEFeatureExtractor()
_explainer: ShapExplainer | None = None

def _get_explainer():
    global _explainer
    if _explainer is None:
        _explainer = ShapExplainer()
    return _explainer

@router.get("/shap")
def explain_shap(file_path: str = Query(...), top_k: int = Query(20, ge=1, le=50)):
    p = Path(file_path)
    # validar traversal: p.resolve() debe estar bajo /tmp o samples
    if ".." in file_path or not p.exists():
        raise HTTPException(400, "file_path inválido o no existe")
    try:
        feats = _extractor.extract(str(p))
    except Exception as exc:
        raise HTTPException(400, f"Extracción falló: {exc}")
    try:
        result = _get_explainer().explain(feats, top_k=top_k)
    except Exception as exc:
        raise HTTPException(500, f"SHAP falló: {exc}")
    return result
```

Registrar en `backend/app/main.py`: `app.include_router(explain_router)`.

**Integración LLM (opcional F3, no bloqueante):**

En `backend/app/services/llm_service.py`, si `shap_top_features` disponible, inyectar en `prompt_builder.build_llm_prompt()`:

```python
if shap_result and shap_result.get("top_features"):
    llm_context["shap_top_features"] = shap_result["top_features"][:5]
```

**Requisitos de dependencias:**

- `requirements/base.in` → NO `torch` (verificar).
- `requirements/ml.in` → `shap>=0.44.0` (si no existe, `pip install shap`).

**Tests T-12:**

```python
def test_shap_top_features():
    explainer = ShapExplainer()
    feats = np.random.rand(2381).astype(np.float32)
    out = explainer.explain(feats, top_k=20)
    assert "top_features" in out
    assert len(out["top_features"]) == 20
    assert all("shap_value" in f and "feature_name" in f for f in out["top_features"])

def test_explain_shap_endpoint(tmp_path):
    pe = tmp_path/"sample.exe"
    pe.write_bytes(b"MZ" + b"\x00"*200)  # PE mínimo — puede fallar pero endpoint debe validar
    # mock extractor para no depender de PE real
```

---

## Correctness Properties

### Propiedad 1 — Behavioral disabled is noop (T-11)
Para todo `scan_file(path, enable_behavioral=False)`: `"BEHAVIORAL" ∉ detection_phases` y `behavioral_analysis is None`.

### Propiedad 2 — Behavioral elevation thresholds (T-11)
Para todo `risk_score ≥ 0.5` con `operational_status ∈ {CLEAN,SUSPICIOUS}`: `operational_status == DANGEROUS` tras `_run_behavioral_phase`.

### Propiedad 3 — Behavioral timeout graceful (T-11)
Para todo `analyze_process` que excede `BEHAVIORAL_SHIELD_TIMEOUT_SECONDS`: `behavioral_analysis is None` y pipeline continúa sin excepción.

### Propiedad 4 — SHAP top_k invariant (T-12)
Para todo `explain(features, top_k=k)`: `len(top_features) == k` y cada `shap_value` es `float` finito.

### Propiedad 5 — SHAP timeout bounded (T-12)
Para todo `explain()` con `nsamples=100`: `elapsed < 30s` o retorna `error="shap_timeout"` sin 500.

### Propiedad 6 — No torch in base (T-12)
Para todo `requirements/base.in`: `"torch" ∉ content.lower()`.

---

## Implementation Plan

Orden: T-11 → T-12 (T-11 modifica engine ya existente, T-12 es módulo nuevo sin conflicto; pueden ir en paralelo si se desea).

1. **T-11** — añadir flag `enable_behavioral` a `scan_file`/`_scan_file_internal`/`scan_service` + verificar `settings`/`dto` ya existentes + 3 tests + `pytest tests/unit/test_engine.py -v`
2. **T-12** — crear `core/explain/` + `ShapExplainer` + endpoint `GET /explain/shap` + registrar en `main.py` + `requirements/ml.in` + 3 tests + `pytest tests/test_shap* -v`
3. Verificación final: `pytest tests/ -v` 0 nuevos FAILED, `grep -i torch requirements/base.in` vacío, `curl /explain/shap?file_path=samples/sample1.exe` retorna 200
