# F2 — Evidence Contract + Correlation Engine

**Estado:** FINALIZADA (sin YARA, sin CNN, sin cambios ONNX/scaler)
**Fecha:** 2026-09-06
**Autores:** F2 Final — ShadowNet Defender

## Objetivo
Eliminar `last writer wins` y scoring con escalas incompatibles. Cada capa produce `Evidence` independiente; `CorrelationEngine` emite un único `FinalVerdict`.

## Evidence Contract (`core/evidence.py`)

```python
Evidence {
  source: EvidenceSource (ml_onnx/yara/pe_static/overlay/heuristic/dotnet/il_behavioral/cnn)
  verdict: BENIGN|SUSPICIOUS|MALICIOUS|UNKNOWN
  score_raw, score_norm (0-1), scale, severity, operational_status
  reliability: DETERMINISTIC|HIGH|MEDIUM|LOW|DEGRADED (peso 1.0/0.85/0.6/0.35/0.25)
  evidence_group: pe_heuristic|overlay_forensic|dotnet_meta|il_semantic|ml_prob|yara_sig|cnn_prob
  indicators, reasons, metadata, confidence, status (OK/DEGRADED/UNAVAILABLE/ERROR), timestamp
}
```

- `score_raw` preservado, `score_norm = raw/ScaleMax` (`ML 1.0`, `PE 50`, `Overlay 60`, `Heuristic/DOTNET/IL 100`).
- `UNAVAILABLE`/`DEGRADED` → `verdict UNKNOWN`, nunca `BENIGN`.
- `pe_heuristic` grupo evita doble conteo: `PE` (40) + `Heuristic` (1 descontado) → `max`, no suma.
- `cnn_evidence()` stub extensible sin rediseño.

## Correlation Engine (`core/correlation.py`)

### Scoring
`S = Σ(w_i · s_norm_i) / Σw_i` por grupo (`max` por grupo). `w` por `Reliability`.

### Verdict (puro)
- YARA `MALICIOUS` → `MALICIOUS`
- `coverage<0.30` → `UNKNOWN`
- `IL ≥0.75` → `MALICIOUS`, `≥0.50` → `SUSPICIOUS` (early-exit)
- `≥2 grupos independientes SUSPICIOUS` → `SUSPICIOUS` (fija sample2.exe)
- `S<0.15 BENIGN`, `0.15-0.60 SUSPICIOUS`, `≥0.60 + high→MALICIOUS`

### Risk / Operational (puros, separados)
- `Risk`: max `severity` entre evidencias sospechosas.
- `Operational`: `MALICIOUS→DANGEROUS`, `SUSPICIOUS→SUSPICIOUS`, `BENIGN→CLEAN`, `UNKNOWN→UNKNOWN`, `BENIGN+coverage<0.3→UNKNOWN`.

### Degraded / Contradiction
- `coverage = avail/total`, `contradiction` (ML benign vs 2 suspicious).
- `degraded = coverage<0.3`, `confidence` por cobertura.

## Flujo (`core/engine.py:904` Fase 9)
`scan_file()` → fases 1-8 pueblan `result` → `_run_correlation_phase()` construye `Evidence[]` → `CorrelationEngine.correlate()` → `result["evidences"]/["final_verdict"]/["correlation"]` + legacy `label`/`operational_status`/`risk_level` (compat). `scan_service.py` mapea `FinalVerdict` a `ScanResult` (`unknown→SUSPICIOUS`).

## sample2.exe
`ML 0.0 BENIGN`, `YARA UNAVAILABLE`, `PE 40 SUSPICIOUS (0.8)`, `Overlay 0 BENIGN`, `Heuristic 1 BENIGN (descontado)`, `DOTNET 28 SUSPICIOUS (0.28)`, `IL 4 BENIGN` → `2 grupos (pe_heuristic, dotnet_meta) → SUSPICIOUS/MEDIUM/SUSPICIOUS`, `S=0.22`, `ml_raw 0.0` preservado, `pe` no borrado por `DOTNET_BASELINE_DISCOUNT`.

## Casos A-I
A BENIGN, B PE solo SUSPICIOUS, C PE+DOTNET SUSPICIOUS, D YARA MALICIOUS, E ML 0.8 solo SUSPICIOUS con contradicción, F YARA unavailable+SUSPICIOUS, G cobertura insuficiente UNKNOWN, H doble conteo evitado, I CNN 0.9 SUSPICIOUS. Tests: `tests/test_correlation_cases.py` (9) + `tests/test_evidence_contract.py` (10).

## Compatibilidad
Nuevos campos no rompen DTO; legacy `label`/`risk_score` derivados de `FinalVerdict`. `AGENTS.md:31-32` documenta contrato.

## Pendientes no F2
Persistencia RLS, YARA instalación, scaler drift, paralelización.

## Referencias
- `core/evidence.py:1-100`, `core/correlation.py:84-110` (scoring), `tests/test_correlation_cases.py`
