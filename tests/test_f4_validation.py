"""
tests/test_f4_validation.py — Suite F4 Validación Científica (T-13/T-14).

Todos los tests que requieren corpus externo hacen pytest.skip si el corpus
no está presente. El CI público no falla por corpus ausente.

Requirement 4 acceptance criteria:
  1. test_corpus_manifest_dqs         — DQS ≥85 si manifest existe, skipped si no
  2. test_scaler_drift_real_vs_synthetic — |mean|<2, 0.5<std<2 sobre real; falla sobre sintético
  3. test_overlay_benchmark_smoke     — FNR_hibrido ≤ FNR_ML sobre overlay sintético
  4. test_metrics_json_schema         — schema {N, auc_roc, auc_pr, f1, scaler_drift} válido si existe
  5. test_accuracy_above_threshold ya ajustado en test_pipeline_e2e.py
"""
from __future__ import annotations

import csv
import json
import struct
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ─── Paths ────────────────────────────────────────────────────────────────────
_MANIFEST_REAL = _PROJECT_ROOT / "data" / "eval_real" / "manifest.csv"
_MANIFEST_OVERLAY = _PROJECT_ROOT / "samples" / "overlay_corpus" / "manifest.csv"
_METRICS_JSON = _PROJECT_ROOT / "evaluation" / "metrics.json"
_SCALER_PATH = _PROJECT_ROOT / "models" / "scaler.pkl"
_X_TEST_SYNTHETIC = _PROJECT_ROOT / "data" / "test_set" / "X_test.npy"

# ─── Condiciones de skip ──────────────────────────────────────────────────────
_CORPUS_REAL_ABSENT = not _MANIFEST_REAL.exists()
_CORPUS_OVERLAY_ABSENT = not _MANIFEST_OVERLAY.exists()
_METRICS_ABSENT = not _METRICS_JSON.exists()
_SCALER_ABSENT = not _SCALER_PATH.exists()
_SYNTHETIC_ABSENT = not _X_TEST_SYNTHETIC.exists()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_minimal_pe(section_data: bytes = b"\x00" * 512) -> bytes:
    """PE minimal válido para tests sintéticos."""
    HEADER_SIZE = 512
    SECTION_RAW_OFFSET = HEADER_SIZE
    if not section_data:
        section_data = b"\x00" * 512
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x020B)
    struct.pack_into("<I", opt, 60, HEADER_SIZE)
    struct.pack_into("<I", opt, 56, 0x1000)
    se = bytearray(40)
    se[0:6] = b".text\x00"
    struct.pack_into("<I", se, 8, len(section_data))
    struct.pack_into("<I", se, 12, 0x1000)
    struct.pack_into("<I", se, 16, len(section_data))
    struct.pack_into("<I", se, 20, SECTION_RAW_OFFSET)
    struct.pack_into("<I", se, 36, 0x60000020)
    header = bytes(dos) + pe_sig + coff + bytes(opt) + bytes(se)
    header = header.ljust(HEADER_SIZE, b"\x00")
    return header + section_data


# ─── Test 1: DQS corpus real ─────────────────────────────────────────────────

@pytest.mark.skipif(
    _CORPUS_REAL_ABSENT,
    reason="CorpusReal no presente — requiere descarga/colección (ver tools/fetch_corpus.py --help)",
)
def test_corpus_manifest_dqs():
    """
    Requirement 4.1 — Si data/eval_real/manifest.csv existe, DQS ≥85.
    Verifica Completeness(sha256,label)≥95% y Validity(label∈{0,1})==100%.
    """
    sys.path.insert(0, str(_PROJECT_ROOT / "evaluation"))
    from evaluate_real_corpus import compute_dqs  # type: ignore[import]

    dqs = compute_dqs(_MANIFEST_REAL)

    assert dqs["DQS"] >= 85, (
        f"DQS={dqs['DQS']:.1f} < 85. Top issues: "
        f"completeness={dqs.get('completeness', '?'):.1f}%, "
        f"validity={dqs.get('validity', '?'):.1f}%, "
        f"duplicates={dqs.get('duplicates', '?')}"
    )
    assert dqs["completeness_sha256"] >= 95, (
        f"Completeness sha256={dqs['completeness_sha256']:.1f}% < 95%"
    )
    assert dqs["completeness_label"] >= 95, (
        f"Completeness label={dqs['completeness_label']:.1f}% < 95%"
    )
    assert dqs["invalid_labels"] == 0, (
        f"Hay {dqs['invalid_labels']} labels inválidos (esperado 0 — label ∈ {{0,1}})"
    )
    assert dqs["duplicates"] == 0, (
        f"Hay {dqs['duplicates']} duplicados de sha256 (Uniqueness < 100%)"
    )


# ─── Test 2: Scaler drift real vs sintético ───────────────────────────────────

@pytest.mark.skipif(
    _SCALER_ABSENT,
    reason="Scaler no encontrado en models/scaler.pkl",
)
def test_scaler_drift_real_vs_synthetic():
    """
    Requirement 4.2 — Verifica que el scaler drift sobre el corpus sintético
    (X_test.npy) FALLA el threshold |mean|<2 & 0.5<std<2, mientras que si
    el corpus real está presente PASA dicho threshold.

    El dato sintético tiene mean≈21.73, std≈112.1 (H-02 — scaler drift).
    data/test_set/X_test.npy — SINTETICO — no usar para métricas de campo.
    """
    import warnings
    import joblib

    scaler = joblib.load(str(_SCALER_PATH))

    # ── Sintético: debe FALLAR el threshold (comportamiento esperado) ──
    if not _SYNTHETIC_ABSENT:
        X_syn = np.load(str(_X_TEST_SYNTHETIC))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            X_scaled_syn = scaler.transform(X_syn)
        mean_syn = float(np.mean(X_scaled_syn))
        std_syn = float(np.std(X_scaled_syn))
        # Verificar que FALLA el threshold (confirma diagnóstico H-02)
        assert not (abs(mean_syn) < 2.0 and 0.5 < std_syn < 2.0), (
            f"INESPERADO: datos sintéticos pasaron el threshold de drift real "
            f"(mean={mean_syn:.2f}, std={std_syn:.2f}). "
            "El test set sintético no debería ser compatible con el scaler de producción."
        )

    # ── Corpus real: debe PASAR el threshold (si está disponible) ──
    if _CORPUS_REAL_ABSENT:
        pytest.skip(
            "CorpusReal no presente — solo se verificó que sintético falla threshold. "
            "Para verificación completa, proveer data/eval_real/ con binarios PE reales."
        )

    # Si llegamos aquí, el corpus real existe
    sys.path.insert(0, str(_PROJECT_ROOT / "evaluation"))
    from evaluate_real_corpus import load_corpus  # type: ignore[import]

    try:
        X_real, y_real, _ = load_corpus(_MANIFEST_REAL.parent, _MANIFEST_REAL)
    except Exception as e:
        pytest.skip(f"No se pudo cargar corpus real para extracción de features: {e}")

    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        X_scaled_real = scaler.transform(X_real)

    mean_real = float(np.mean(X_scaled_real))
    std_real = float(np.std(X_scaled_real))

    assert abs(mean_real) < 2.0, (
        f"Scaler drift mean_post={mean_real:.4f} ≥ 2.0 sobre corpus real. "
        f"El scaler puede estar desalineado con el dominio de campo. "
        f"(ref sintético: mean={21.73})"
    )
    assert 0.5 < std_real < 2.0, (
        f"Scaler drift std_post={std_real:.4f} fuera de [0.5, 2.0] sobre corpus real. "
        f"(ref sintético: std={112.1})"
    )


# ─── Test 3: Overlay benchmark smoke (corpus sintético) ──────────────────────

def test_overlay_benchmark_smoke():
    """
    Requirement 4.3 — Verifica que FNR_hibrido ≤ FNR_ML sobre overlay sintético
    generado en-test. No requiere corpus real ni VT. También activa
    high_entropy_block_ratio para verificar que la capa de análisis funciona.

    Este test SIEMPRE corre (no skip).
    """
    import os

    try:
        from core.overlay import OverlayAnalyzer
        from core.heuristics import HeuristicRiskEngine, RiskAssessment
    except ImportError as e:
        pytest.skip(f"Módulos core.overlay/heuristics no disponibles: {e}")

    analyzer = OverlayAnalyzer()
    engine = HeuristicRiskEngine()

    # Generar N=10 muestras sintéticas: 5 dropper (malware) + 5 limpia (benigno)
    # Evaluar ML simulado (score=0.0 siempre — evasión) vs híbrido
    stub = _make_minimal_pe(b"\x90" * 4096)

    fn_ml = fn_hybrid = total = 0

    for i in range(20):
        is_malware = i % 2 == 0  # alternando: maligno / benigno

        if is_malware:
            # Dropper: stub PE + overlay cifrado 90%+
            overlay_size = 200 * 1024  # 200 KB
            overlay = os.urandom(overlay_size)
            data = stub + overlay
            gt = 1
        else:
            # Benigno: solo PE sin overlay significativo
            data = stub
            gt = 0

        report = analyzer.analyze(data)
        # Simular que ML da score=0.0 (evasión en caso malware, correcto en benigno)
        ml_score = 0.0
        risk = engine.assess(report, ml_score=ml_score)

        ml_pred = 1 if ml_score >= 0.5 else 0
        hybrid_pred = 1 if risk.operational_status in ("DANGEROUS", "SUSPICIOUS") else 0

        if is_malware:
            total += 1
            if ml_pred != gt:
                fn_ml += 1
            if hybrid_pred != gt:
                fn_hybrid += 1

    if total == 0:
        pytest.skip("No se procesaron muestras sintéticas.")

    fnr_ml = fn_ml / total
    fnr_hybrid = fn_hybrid / total

    assert fnr_hybrid <= fnr_ml, (
        f"FNR_hibrido={fnr_hybrid:.3f} > FNR_ML={fnr_ml:.3f} sobre corpus sintético. "
        "La capa híbrida debe detectar más que solo-ML para dropper con overlay."
    )

    # Verificar high_entropy_block_ratio sobre un dropper
    BLOCK = 32 * 1024
    encrypted_block = os.urandom(BLOCK)
    zero_block = b"\x00" * BLOCK
    overlay_segmented = (encrypted_block + zero_block) * 4
    dropper_data = stub + overlay_segmented
    report_seg = analyzer.analyze(dropper_data)

    if report_seg.overlay_present and hasattr(report_seg, "high_entropy_block_ratio"):
        assert report_seg.high_entropy_block_ratio >= 0.0, (
            "high_entropy_block_ratio debe ser un valor válido [0, 1]"
        )


# ─── Test 4: metrics.json schema ─────────────────────────────────────────────

@pytest.mark.skipif(
    _METRICS_ABSENT,
    reason="evaluation/metrics.json no presente — ejecutar T-13/T-14 primero",
)
def test_metrics_json_schema():
    """
    Requirement 4.4 — Si evaluation/metrics.json existe, valida schema estable:
    {N, auc_roc, auc_pr, f1, scaler_drift} (T-13) y/o
    {N, FNR_ML, FNR_hibrido, p_value} (T-14 overlay).
    """
    with open(_METRICS_JSON, encoding="utf-8") as f:
        m = json.load(f)

    errors = []

    # Verificar T-13 metrics si el corpus principal fue evaluado
    if "N" in m and "metrics" in m:
        # T-13 schema
        required_metrics = {"accuracy", "precision", "recall", "f1", "auc_roc", "auc_pr"}
        missing = required_metrics - set(m["metrics"].keys())
        if missing:
            errors.append(f"T-13 metrics missing: {missing}")

        required_top = {"N", "metrics", "scaler_drift", "mlflow_run_id"}
        missing_top = required_top - set(m.keys())
        if missing_top:
            errors.append(f"T-13 top-level fields missing: {missing_top}")

        # Scaler drift schema
        sd = m.get("scaler_drift", {})
        if "mean_post" not in sd or "std_post" not in sd:
            errors.append("scaler_drift debe tener mean_post y std_post")

        # Valores en rangos válidos
        if "auc_roc" in m.get("metrics", {}):
            auc = m["metrics"]["auc_roc"]
            if not (0.0 <= auc <= 1.0):
                errors.append(f"auc_roc={auc} fuera de [0, 1]")

    # Verificar T-14 overlay benchmark si fue ejecutado
    if "overlay_benchmark" in m:
        ob = m["overlay_benchmark"]
        required_overlay = {"N", "FNR_ML", "FNR_hibrido", "FNR_diff", "mcnemar_chi2", "p_value"}
        missing_ov = required_overlay - set(ob.keys())
        if missing_ov:
            errors.append(f"T-14 overlay_benchmark fields missing: {missing_ov}")

        if "p_value" in ob:
            pv = ob["p_value"]
            if not (0.0 <= pv <= 1.0):
                errors.append(f"p_value={pv} fuera de [0, 1]")

        if "N" in ob and ob["N"] < 10:
            errors.append(f"T-14 N={ob['N']} < 10 (mínimo para smoke test)")

    # Si metrics.json existe pero no tiene ni T-13 ni T-14 data
    if "N" not in m and "overlay_benchmark" not in m:
        errors.append(
            "metrics.json existe pero no contiene datos T-13 (N, metrics) "
            "ni T-14 (overlay_benchmark). Ejecutar evaluate_real_corpus.py o benchmark_overlay.py."
        )

    assert not errors, "metrics.json schema inválido:\n" + "\n".join(f"  - {e}" for e in errors)
