"""
evaluation/benchmark_overlay.py — T-14 Benchmark ML vs híbrido sobre CorpusOverlay.

Justificación sample size (experiment-designer):
    baseline FNR solo-ML ≈ 0.10→0.18 (Δ=0.08 absolute, baseline=0.10)
    → n≈296 no pareado (test proporciones).
    McNemar PAREADO → correlación intra-par reduce varianza:
    N=100 overlay es mínimo aceptable, N=200 es ideal.
    Ver: design.md sección T-14.

Uso:
    python evaluation/benchmark_overlay.py --corpus samples/overlay_corpus/ [--help]

Salida:
    evaluation/metrics.json  (actualizado con overlay metrics)
    docs/academico/figures/fig_overlay_benchmark.png
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import warnings
from pathlib import Path
from typing import Optional

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import numpy as np

# ─── Constantes ───────────────────────────────────────────────────────────────

CORPUS_DIR = _PROJECT_ROOT / "samples" / "overlay_corpus"
MANIFEST_FNAME = "manifest.csv"
SCALER_PATH = _PROJECT_ROOT / "models" / "scaler.pkl"
MODEL_PATH = _PROJECT_ROOT / "models" / "best_model.onnx"
EVAL_REAL_DIR = _PROJECT_ROOT / "data" / "eval_real"
METRICS_OUT = _PROJECT_ROOT / "evaluation" / "metrics.json"
FIGURES_DIR = _PROJECT_ROOT / "docs" / "academico" / "figures"
FIG_OUT = FIGURES_DIR / "fig_overlay_benchmark.png"
FEATURE_DIM = 2381
SEED = 42
# Bonferroni α/3 para múltiples métricas testeadas (FPR@TPR90, TPR@FPR1, F1)
ALPHA = 0.05 / 3

# Referencia sample1.exe
SAMPLE1_OVERLAY_RATIO = 0.987


# ─── DQS (reutilizado de evaluate_real_corpus) ────────────────────────────────

def compute_dqs_overlay(manifest_path: Path) -> dict:
    """DQS para manifest de overlay con columnas overlay_ratio y overlay_entropy."""
    import re
    rows = []
    with open(manifest_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames or [])
        for r in reader:
            rows.append(r)

    N = len(rows)
    if N == 0:
        return {"DQS": 0, "N": 0, "error": "manifest vacío"}

    # Completeness sha256
    missing_sha = sum(1 for r in rows if not r.get("sha256", "").strip())
    completeness_sha256 = 100 * (1 - missing_sha / N)
    # overlay_ratio puede ser nulo (MCAR — PE sin overlay) → reportar null%, no imputar
    null_ratio = sum(1 for r in rows if not r.get("overlay_ratio", "").strip())
    null_entropy = sum(1 for r in rows if not r.get("overlay_entropy", "").strip())
    completeness = (completeness_sha256 + 100) / 2  # sha256 obligatorio, resto esperado nulo

    # Validity sha256
    sha256_re = re.compile(r"^[0-9a-fA-F]{64}$")
    invalid_sha = sum(
        1 for r in rows if not sha256_re.match(r.get("sha256", "").strip())
    )
    validity = 100 * (1 - invalid_sha / N)

    # Uniqueness
    sha256s = [r.get("sha256", "").strip().lower() for r in rows]
    duplicates = N - len(set(sha256s))
    uniqueness = 100 * (1 - duplicates / N)

    consistency = 100.0 if {"sha256", "overlay_ratio", "overlay_entropy", "vt_report"}.issubset(fieldnames) else 70.0
    timeliness = 100.0 if "vt_report" in fieldnames else 50.0

    dqs = (0.30 * completeness + 0.25 * consistency +
           0.20 * validity + 0.15 * uniqueness + 0.10 * timeliness)

    return {
        "DQS": round(dqs, 2),
        "N": N,
        "completeness_sha256": round(completeness_sha256, 2),
        "null_overlay_ratio": null_ratio,
        "null_overlay_entropy": null_entropy,
        "missingness_overlay_ratio": "MCAR (PE sin overlay → nulo esperado, no imputar)",
        "missingness_overlay_entropy": "MAR dado overlay_ratio=0 (no imputar con media)",
        "validity": round(validity, 2),
        "uniqueness": round(uniqueness, 2),
        "duplicates": duplicates,
    }


# ─── Inferencia ONNX ──────────────────────────────────────────────────────────

def ort_predict_single(session, features_scaled: np.ndarray) -> float:
    input_name = session.get_inputs()[0].name
    result = session.run(None, {input_name: features_scaled.reshape(1, -1).astype(np.float32)})
    raw = float(result[0].flatten()[0])
    if raw > 1.0 or raw < 0.0:
        raw = 1.0 / (1.0 + np.exp(-raw))
    return raw


# ─── Wilson confidence interval ───────────────────────────────────────────────

def wilson_ci(p: float, n: int, z: float = 1.96) -> tuple[float, float]:
    """Intervalo de confianza Wilson 95%."""
    if n == 0:
        return (0.0, 0.0)
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    delta = z * np.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return (max(0.0, center - delta), min(1.0, center + delta))


# ─── McNemar test ─────────────────────────────────────────────────────────────

def mcnemar_test(b: int, c: int) -> tuple[float, float]:
    """
    McNemar χ² con corrección de continuidad de Yates.
    b = ML wrong & Híbrido correct (ganancia)
    c = ML correct & Híbrido wrong (pérdida)
    """
    from scipy.stats import chi2
    if (b + c) == 0:
        return (0.0, 1.0)
    chi2_val = (abs(b - c) - 1) ** 2 / (b + c)
    p_value = float(1 - chi2.cdf(chi2_val, df=1))
    return (round(chi2_val, 4), round(p_value, 6))


# ─── FPR guardrail sobre benignos de eval_real ────────────────────────────────

def measure_guardrail_fpr(session, scaler, eval_real_dir: Path) -> Optional[dict]:
    """
    Mide FPR del sistema híbrido sobre benignos de data/eval_real.
    Devuelve None si eval_real no está disponible.
    """
    if not eval_real_dir.exists():
        return None

    manifest_path = eval_real_dir / MANIFEST_FNAME
    if not manifest_path.exists():
        return None

    try:
        from extractors.extractor import PEFeatureExtractor
        extractor = PEFeatureExtractor()
        from core.engine import ShadowNetEngine
        engine = ShadowNetEngine()
    except Exception:
        return None

    rows = []
    with open(manifest_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r.get("label", "").strip() == "0":  # solo benignos
                rows.append(r)

    if not rows:
        return None

    fp_ml = fp_hybrid = total = 0
    for row in rows[:200]:  # sample de hasta 200 benignos para eficiencia
        sha = row.get("sha256", "").strip()
        candidates = list(eval_real_dir.rglob(f"{sha}*")) + list(eval_real_dir.rglob(f"*{sha[:8]}*"))
        if not candidates:
            continue
        try:
            features = extractor.extract_features(str(candidates[0]))
            if len(features) != FEATURE_DIM:
                continue
            X_s = scaler.transform([features])
            score_ml = ort_predict_single(session, X_s[0])
            if score_ml >= 0.5:
                fp_ml += 1
            result = engine.scan_file(str(candidates[0]))
            op = getattr(result, "operational_status", None) or result.get("operational_status", "")
            if str(op).upper() == "DANGEROUS":
                fp_hybrid += 1
            total += 1
        except Exception:
            continue

    if total == 0:
        return None

    return {
        "n_benign_tested": total,
        "FPR_ML": round(fp_ml / total, 4),
        "FPR_hybrid": round(fp_hybrid / total, 4),
        "FPR_diff": round((fp_hybrid - fp_ml) / total, 4),
        "guardrail_ok": (fp_hybrid - fp_ml) / total <= 0.02,
    }


# ─── Figura ───────────────────────────────────────────────────────────────────

def plot_benchmark(metrics: dict, overlay_ratios: list[float]) -> None:
    """
    fig_overlay_benchmark.png:
    Subplot 1: barras FNR_ML vs FNR_hibrido con intervalos Wilson + anotación p-value.
    Subplot 2: histograma overlay_ratio con línea sample1.exe=98.7%.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[WARN] matplotlib no instalado — figura omitida.")
        return

    N = metrics["N"]
    fnr_ml = metrics["FNR_ML"]
    fnr_h = metrics["FNR_hibrido"]
    p_val = metrics.get("p_value", 1.0)
    chi2_val = metrics.get("mcnemar_chi2", 0.0)

    # Wilson CI
    ci_ml = wilson_ci(fnr_ml, N)
    ci_h = wilson_ci(fnr_h, N)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle("T-14: Benchmark ML vs. Híbrido — Corpus Overlay", fontsize=14, fontweight="bold")

    # Subplot 1 — FNR comparison
    systems = ["Solo-ML (ONNX)", "Híbrido multicapa"]
    fnrs = [fnr_ml, fnr_h]
    colors = ["#e74c3c", "#27ae60"]
    bars = ax1.bar(systems, fnrs, color=colors, alpha=0.8, width=0.4)

    # Intervalos Wilson
    ax1.errorbar(
        [0, 1], fnrs,
        yerr=[[fnrs[i] - (ci_ml[0] if i == 0 else ci_h[0]) for i in range(2)],
              [(ci_ml[1] if i == 0 else ci_h[1]) - fnrs[i] for i in range(2)]],
        fmt="none", color="black", capsize=6, linewidth=2,
    )

    # Anotación p-value
    sig = "***" if p_val < 0.001 else ("**" if p_val < 0.01 else ("*" if p_val < 0.05 else "ns"))
    ax1.annotate(
        f"McNemar χ²={chi2_val:.3f}\np={p_val:.4f} {sig}\n(Bonferroni α={ALPHA:.4f})",
        xy=(0.5, max(fnrs) * 1.05),
        xycoords=("axes fraction", "data"),
        ha="center", fontsize=9,
        bbox=dict(boxstyle="round,pad=0.3", facecolor="lightyellow", edgecolor="gray"),
    )
    ax1.set_ylabel("False Negative Rate (FNR)")
    ax1.set_title(f"FNR sobre CorpusOverlay (N={N})\nWilson CI 95%")
    ax1.set_ylim(0, min(1.0, max(fnrs) * 1.4 + 0.05))
    ax1.grid(axis="y", alpha=0.3)

    # Subplot 2 — histograma overlay_ratio
    if overlay_ratios:
        ax2.hist(overlay_ratios, bins=20, color="#3498db", alpha=0.7, edgecolor="white")
        ax2.axvline(
            SAMPLE1_OVERLAY_RATIO, color="#e74c3c", linewidth=2,
            linestyle="--", label=f"sample1.exe = {SAMPLE1_OVERLAY_RATIO:.1%}",
        )
        ax2.set_xlabel("overlay_ratio")
        ax2.set_ylabel("Frecuencia")
        ax2.set_title("Distribución overlay_ratio\nCorpusOverlay")
        ax2.legend(fontsize=9)
        ax2.grid(alpha=0.3)

    plt.tight_layout()
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(FIG_OUT), dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[T-14] Figura guardada: {FIG_OUT}")


# ─── Benchmark principal ──────────────────────────────────────────────────────

def benchmark(corpus_dir: Path) -> dict:
    """Pipeline completo T-14."""
    from scipy.stats import chi2 as _chi2_dist  # noqa: F401 — trigger import early

    manifest_path = corpus_dir / MANIFEST_FNAME
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest no encontrado: {manifest_path}")

    print("[T-14] Calculando DQS del corpus overlay...")
    dqs = compute_dqs_overlay(manifest_path)
    print(f"       DQS={dqs['DQS']:.1f}/100  N={dqs['N']}")
    print(f"       null overlay_ratio={dqs['null_overlay_ratio']} ({dqs['missingness_overlay_ratio']})")

    # Cargar manifest
    rows = []
    overlay_ratios: list[float] = []
    with open(manifest_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(r)
            try:
                overlay_ratios.append(float(r.get("overlay_ratio", "") or "nan"))
            except ValueError:
                overlay_ratios.append(float("nan"))

    overlay_ratios_valid = [v for v in overlay_ratios if not np.isnan(v)]
    print(f"       overlay_ratio — min={min(overlay_ratios_valid, default=0):.2f}  "
          f"max={max(overlay_ratios_valid, default=0):.2f}  "
          f"mean={np.mean(overlay_ratios_valid or [0]):.2f}")

    import joblib
    import onnxruntime as ort
    scaler = joblib.load(str(SCALER_PATH))
    session = ort.InferenceSession(str(MODEL_PATH))

    try:
        from extractors.extractor import PEFeatureExtractor
        from core.engine import ShadowNetEngine
        extractor = PEFeatureExtractor()
        engine = ShadowNetEngine()
    except Exception as exc:
        raise RuntimeError(f"No se pudo inicializar engine/extractor: {exc}") from exc

    # Tabla McNemar 2×2
    a = b = c = d = 0  # a=ambos ok, b=ML wrong/H ok, c=ML ok/H wrong, d=ambos wrong

    for row in rows:
        sha = row.get("sha256", "").strip()
        candidates = list(corpus_dir.rglob(f"{sha}*")) + list(corpus_dir.rglob(f"*{sha[:8]}*"))
        if not candidates:
            continue
        sample_path = candidates[0]

        try:
            features = extractor.extract_features(str(sample_path))
            if len(features) != FEATURE_DIM:
                continue
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                X_scaled = scaler.transform([features])
            score_ml = ort_predict_single(session, X_scaled[0])
            correct_ml = score_ml >= 0.5  # GT=malware para todo overlay corpus

            result = engine.scan_file(str(sample_path))
            op = getattr(result, "operational_status", None) or result.get("operational_status", "")
            correct_h = str(op).upper() == "DANGEROUS"

            if correct_ml and correct_h:
                a += 1
            elif not correct_ml and correct_h:
                b += 1  # ganancia híbrido
            elif correct_ml and not correct_h:
                c += 1  # pérdida híbrido
            else:
                d += 1
        except Exception:
            continue

    N_total = a + b + c + d
    if N_total == 0:
        raise RuntimeError("No se procesó ninguna muestra del corpus overlay.")

    fnr_ml = 1.0 - (a + c) / N_total
    fnr_h = 1.0 - (a + b) / N_total
    chi2_val, p_value = mcnemar_test(b, c)

    print(f"\n[T-14] McNemar tabla 2×2: a={a} b={b} c={c} d={d}")
    print(f"       N={N_total}  FNR_ML={fnr_ml:.4f}  FNR_hibrido={fnr_h:.4f}")
    print(f"       McNemar χ²={chi2_val:.4f}  p={p_value:.6f}  "
          + ("✅ p<α" if p_value < ALPHA else "⚠️  p≥α"))

    # Guardrail FPR sobre benignos de eval_real
    guardrail = measure_guardrail_fpr(session, scaler, EVAL_REAL_DIR)
    if guardrail:
        gok = guardrail["guardrail_ok"]
        print(f"       Guardrail FPR: diff={guardrail['FPR_diff']:+.4f}  "
              + ("✅ ≤0.02" if gok else "❌ >0.02"))
    else:
        print("       Guardrail FPR: no disponible (eval_real ausente)")

    metrics_overlay = {
        "N": N_total,
        "table_2x2": {"a": a, "b": b, "c": c, "d": d},
        "FNR_ML": round(fnr_ml, 4),
        "FNR_hibrido": round(fnr_h, 4),
        "FNR_diff": round(fnr_ml - fnr_h, 4),
        "mcnemar_chi2": chi2_val,
        "p_value": p_value,
        "alpha_bonferroni": round(ALPHA, 6),
        "significant": p_value < ALPHA,
        "guardrail_FPR": guardrail,
        "dqs_overlay": dqs,
    }

    # Actualizar metrics.json
    existing = {}
    if METRICS_OUT.exists():
        with open(METRICS_OUT, encoding="utf-8") as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                pass

    existing["overlay_benchmark"] = metrics_overlay
    METRICS_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(METRICS_OUT, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)
    print(f"[T-14] metrics.json actualizado: {METRICS_OUT}")

    plot_benchmark(metrics_overlay, overlay_ratios_valid)
    return metrics_overlay


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "T-14 — Benchmark ML vs Híbrido sobre CorpusOverlay (N≥100 PE overlay).\n\n"
            "Sample size justificación:\n"
            "  FNR baseline=0.10→0.18 (Δ=0.08), α=0.05, power=0.8\n"
            "  → n≈296 no pareado; McNemar pareado → N=100 mínimo, N=200 ideal.\n"
            "  (ver design.md y requirements.md sección T-14.4)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=CORPUS_DIR,
        help=f"Directorio con overlay corpus y manifest.csv. Default: {CORPUS_DIR}",
    )
    parser.add_argument(
        "--dqs-only",
        action="store_true",
        help="Solo calcular DQS del corpus overlay sin correr benchmark.",
    )
    args = parser.parse_args()

    corpus_dir = args.corpus.resolve()

    if not corpus_dir.exists():
        print(f"[SKIP] Corpus overlay no encontrado en {corpus_dir}.", file=sys.stderr)
        sys.exit(0)

    if args.dqs_only:
        manifest_path = corpus_dir / MANIFEST_FNAME
        if not manifest_path.exists():
            print(f"[ERROR] Manifest no encontrado: {manifest_path}", file=sys.stderr)
            sys.exit(1)
        dqs = compute_dqs_overlay(manifest_path)
        print(json.dumps(dqs, indent=2))
        return

    benchmark(corpus_dir)


if __name__ == "__main__":
    main()
