"""
evaluation/evaluate_real_corpus.py — T-13 Validación científica sobre CorpusReal.

Uso:
    python evaluation/evaluate_real_corpus.py --corpus data/eval_real/ [--help]

Salida:
    evaluation/metrics.json  {corpus, N, metrics, scaler_drift, mlflow_run_id}
    evaluation/DATA_QUALITY_REPORT.md (sección T-13)
"""
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import sys
import warnings
from pathlib import Path
from typing import Optional

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ─── Guards de importación ────────────────────────────────────────────────────

def _require(pkg: str, pip_name: Optional[str] = None) -> None:
    import importlib
    if importlib.util.find_spec(pkg) is None:
        print(f"[ERROR] Paquete requerido no encontrado: {pkg}. "
              f"Instalar con: pip install {pip_name or pkg}", file=sys.stderr)
        sys.exit(1)

_require("numpy", "numpy")
_require("sklearn", "scikit-learn")
_require("onnxruntime", "onnxruntime")
_require("joblib", "joblib")

import numpy as np

# ─── Constantes ───────────────────────────────────────────────────────────────

CORPUS_DIR = _PROJECT_ROOT / "data" / "eval_real"
MANIFEST_FNAME = "manifest.csv"
SCALER_PATH = _PROJECT_ROOT / "models" / "scaler.pkl"
MODEL_PATH = _PROJECT_ROOT / "models" / "best_model.onnx"
METRICS_OUT = _PROJECT_ROOT / "evaluation" / "metrics.json"
DQR_PATH = _PROJECT_ROOT / "evaluation" / "DATA_QUALITY_REPORT.md"
FEATURE_DIM = 2381
MIN_DQS = 85
SKFOLD_K = 5
SEED = 42

# Valores de referencia sintéticos (H-02)
SYNTHETIC_MEAN_POST = 21.73
SYNTHETIC_STD_POST = 112.1


# ─── DQS (data-quality-auditor) ───────────────────────────────────────────────

def compute_dqs(manifest_path: Path) -> dict:
    """
    DQS = 0.30*Completeness + 0.25*Consistency + 0.20*Validity
          + 0.15*Uniqueness + 0.10*Timeliness
    Devuelve dict con DQS (0-100) y breakdown por dimensión.
    """
    required_cols = {"sha256", "label", "source"}
    rows = []
    with open(manifest_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames or [])
        for r in reader:
            rows.append(r)

    N = len(rows)
    if N == 0:
        return {"DQS": 0, "N": 0, "error": "manifest vacío"}

    # Completeness: sha256, label, source no nulos
    missing_sha = sum(1 for r in rows if not r.get("sha256", "").strip())
    missing_label = sum(1 for r in rows if not r.get("label", "").strip())
    missing_source = sum(1 for r in rows if not r.get("source", "").strip())
    completeness_sha256 = 100 * (1 - missing_sha / N)
    completeness_label = 100 * (1 - missing_label / N)
    completeness = (completeness_sha256 + completeness_label +
                    100 * (1 - missing_source / N)) / 3

    # Validity: label ∈ {0, 1}, sha256 hex 64
    invalid_label = sum(
        1 for r in rows if r.get("label", "").strip() not in ("0", "1")
    )
    import re
    sha256_re = re.compile(r"^[0-9a-fA-F]{64}$")
    invalid_sha = sum(
        1 for r in rows if not sha256_re.match(r.get("sha256", "").strip())
    )
    validity = 100 * (1 - (invalid_label + invalid_sha) / (2 * N))

    # Uniqueness: 0 duplicados sha256
    sha256s = [r.get("sha256", "").strip().lower() for r in rows]
    duplicates = N - len(set(sha256s))
    uniqueness = 100 * (1 - duplicates / N)

    # Consistency: all required cols present
    consistency = 100.0 if required_cols.issubset(fieldnames) else 60.0

    # Timeliness: if vt_report col present → 100, else 50
    timeliness = 100.0 if "vt_report" in fieldnames else 50.0

    dqs = (0.30 * completeness + 0.25 * consistency +
           0.20 * validity + 0.15 * uniqueness + 0.10 * timeliness)

    return {
        "DQS": round(dqs, 2),
        "N": N,
        "completeness": round(completeness, 2),
        "completeness_sha256": round(completeness_sha256, 2),
        "completeness_label": round(completeness_label, 2),
        "consistency": round(consistency, 2),
        "validity": round(validity, 2),
        "uniqueness": round(uniqueness, 2),
        "timeliness": round(timeliness, 2),
        "duplicates": duplicates,
        "invalid_labels": invalid_label,
        "invalid_sha256": invalid_sha,
    }


# ─── Carga de corpus ──────────────────────────────────────────────────────────

def load_corpus(corpus_dir: Path, manifest_path: Path):
    """
    Carga corpus y extrae features. Devuelve (X, y, operational_status_list).
    Requiere core.engine y extractors disponibles.
    """
    from extractors.extractor import PEFeatureExtractor
    extractor = PEFeatureExtractor()

    rows = []
    with open(manifest_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    X_list, y_list, op_status_list = [], [], []

    for row in rows:
        sha = row.get("sha256", "").strip()
        label = int(row.get("label", "-1").strip())
        if label not in (0, 1):
            continue

        # Buscar el binario (malware/ o benign/ o raíz)
        candidates = list(corpus_dir.rglob(f"*{sha[:8]}*")) + list(
            corpus_dir.rglob(f"{sha}*")
        )
        if not candidates:
            continue
        bin_path = candidates[0]

        try:
            features = extractor.extract_features(str(bin_path))
            if len(features) != FEATURE_DIM:
                continue
            X_list.append(features)
            y_list.append(label)
            op_status_list.append(None)  # poblado en benchmark híbrido
        except Exception:
            continue

    if not X_list:
        raise RuntimeError(
            "No se pudieron extraer features. Verificar corpus y extractor."
        )

    return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=int), op_status_list


# ─── Inferencia ONNX ──────────────────────────────────────────────────────────

def ort_predict(session, X_scaled: np.ndarray) -> np.ndarray:
    """Inferencia ONNX sobre batch. Devuelve array de probabilidades [0,1]."""
    input_name = session.get_inputs()[0].name
    results = session.run(None, {input_name: X_scaled.astype(np.float32)})
    raw = results[0].flatten()
    # Sigmoid si logit crudo
    if raw.max() > 1.0 or raw.min() < 0.0:
        raw = 1.0 / (1.0 + np.exp(-raw))
    return raw


# ─── Métricas operativas ──────────────────────────────────────────────────────

def fpr_at_tpr(y_true, y_score, target_tpr: float = 0.90):
    """FPR cuando TPR ≥ target_tpr."""
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(y_true, y_score)
    idx = np.searchsorted(tpr, target_tpr)
    idx = min(idx, len(fpr) - 1)
    return float(fpr[idx])


def tpr_at_fpr(y_true, y_score, target_fpr: float = 0.01):
    """TPR cuando FPR ≤ target_fpr."""
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(y_true, y_score)
    idx = np.searchsorted(fpr, target_fpr, side="right") - 1
    idx = max(idx, 0)
    return float(tpr[idx])


# ─── Evaluación principal ─────────────────────────────────────────────────────

def evaluate(corpus_dir: Path) -> dict:
    """Pipeline completo T-13."""
    manifest_path = corpus_dir / MANIFEST_FNAME

    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest no encontrado: {manifest_path}")
    if not SCALER_PATH.exists():
        raise FileNotFoundError(f"Scaler no encontrado: {SCALER_PATH}")
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Modelo ONNX no encontrado: {MODEL_PATH}")

    # 1. DQS gate
    print("[T-13] Calculando DQS del corpus...")
    dqs_report = compute_dqs(manifest_path)
    print(f"       DQS={dqs_report['DQS']:.1f}/100  N={dqs_report['N']}")

    if dqs_report["DQS"] < MIN_DQS:
        raise ValueError(
            f"DQS {dqs_report['DQS']:.1f} < {MIN_DQS}. "
            "El corpus no cumple el umbral mínimo de calidad."
        )

    # 2. Cargar corpus + extraer features
    print("[T-13] Extrayendo features del corpus...")
    X, y, _ = load_corpus(corpus_dir, manifest_path)
    N = len(y)
    print(f"       Muestras válidas: {N}  (malware={y.sum()}, benign={N - y.sum()})")

    # 3. Scaler drift
    import joblib
    scaler = joblib.load(str(SCALER_PATH))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        X_scaled = scaler.transform(X)
    drift = {
        "mean_post": float(np.mean(X_scaled)),
        "std_post": float(np.std(X_scaled)),
        "mean_synthetic_ref": SYNTHETIC_MEAN_POST,
        "std_synthetic_ref": SYNTHETIC_STD_POST,
    }
    print(f"       Scaler drift — mean={drift['mean_post']:.4f}  std={drift['std_post']:.4f}  "
          f"(ref sintético: mean={SYNTHETIC_MEAN_POST}, std={SYNTHETIC_STD_POST})")

    # 4. StratifiedKFold + MLflow
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, average_precision_score,
    )
    import onnxruntime as ort

    session = ort.InferenceSession(str(MODEL_PATH))
    skf = StratifiedKFold(n_splits=SKFOLD_K, shuffle=True, random_state=SEED)

    fold_metrics: dict[str, list] = {
        "accuracy": [], "precision": [], "recall": [], "f1": [],
        "auc_roc": [], "auc_pr": [], "fpr_at_tpr90": [], "tpr_at_fpr1": [],
        "train_auc_roc": [],
    }

    mlflow_available = False
    mlflow_run_id = "mlflow_not_installed"
    try:
        import mlflow
        mlflow_available = True
    except ImportError:
        print("       [WARN] mlflow no instalado — saltando tracking MLflow.")

    ctx_manager = mlflow.start_run(run_name="evaluate_real_corpus") if mlflow_available else _null_ctx()

    with ctx_manager as run:
        for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X_scaled, y)):
            X_tr, X_te = X_scaled[train_idx], X_scaled[test_idx]
            y_tr, y_te = y[train_idx], y[test_idx]

            proba_te = ort_predict(session, X_te)
            proba_tr = ort_predict(session, X_tr)
            y_pred = (proba_te >= 0.5).astype(int)

            fold_metrics["accuracy"].append(accuracy_score(y_te, y_pred))
            fold_metrics["precision"].append(
                precision_score(y_te, y_pred, zero_division=0))
            fold_metrics["recall"].append(recall_score(y_te, y_pred, zero_division=0))
            fold_metrics["f1"].append(f1_score(y_te, y_pred, zero_division=0))

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                fold_metrics["auc_roc"].append(roc_auc_score(y_te, proba_te))
                fold_metrics["auc_pr"].append(average_precision_score(y_te, proba_te))
                fold_metrics["train_auc_roc"].append(roc_auc_score(y_tr, proba_tr))

            fold_metrics["fpr_at_tpr90"].append(fpr_at_tpr(y_te, proba_te, 0.90))
            fold_metrics["tpr_at_fpr1"].append(tpr_at_fpr(y_te, proba_te, 0.01))

            print(f"       Fold {fold_idx+1}/{SKFOLD_K} — "
                  f"AUC-ROC={fold_metrics['auc_roc'][-1]:.4f}  "
                  f"F1={fold_metrics['f1'][-1]:.4f}")

        # Agregar mean±std
        aggregated = {}
        for k, vals in fold_metrics.items():
            aggregated[k] = {"mean": float(np.mean(vals)), "std": float(np.std(vals))}

        overfit_gap = (aggregated["train_auc_roc"]["mean"]
                       - aggregated["auc_roc"]["mean"])

        if mlflow_available and run is not None:
            for k, v in aggregated.items():
                mlflow.log_metric(f"{k}_mean", v["mean"])
                mlflow.log_metric(f"{k}_std", v["std"])
            mlflow.log_metric("overfit_gap", overfit_gap)
            mlflow.log_metric("scaler_mean_post", drift["mean_post"])
            mlflow.log_metric("scaler_std_post", drift["std_post"])
            mlflow_run_id = run.info.run_id if hasattr(run, "info") else "unknown"

    # 5. Serializar metrics.json
    metrics_payload = {
        "corpus": str(corpus_dir),
        "N": N,
        "metrics": {
            "accuracy": aggregated["accuracy"]["mean"],
            "precision": aggregated["precision"]["mean"],
            "recall": aggregated["recall"]["mean"],
            "f1": aggregated["f1"]["mean"],
            "auc_roc": aggregated["auc_roc"]["mean"],
            "auc_pr": aggregated["auc_pr"]["mean"],
            "fpr_at_tpr90": aggregated["fpr_at_tpr90"]["mean"],
            "tpr_at_fpr1": aggregated["tpr_at_fpr1"]["mean"],
        },
        "metrics_std": {k: v["std"] for k, v in aggregated.items()},
        "overfit_gap": overfit_gap,
        "scaler_drift": drift,
        "dqs": dqs_report,
        "mlflow_run_id": mlflow_run_id,
    }

    METRICS_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(METRICS_OUT, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2, ensure_ascii=False)
    print(f"\n[T-13] metrics.json guardado en {METRICS_OUT}")
    print(f"       AUC-ROC={aggregated['auc_roc']['mean']:.4f}±{aggregated['auc_roc']['std']:.4f}")
    print(f"       F1     ={aggregated['f1']['mean']:.4f}±{aggregated['f1']['std']:.4f}")
    print(f"       Overfit gap (train-test AUC)={overfit_gap:.4f}"
          + (" ⚠️  >0.05" if overfit_gap > 0.05 else " ✅"))

    _append_dqr(dqs_report, metrics_payload)
    return metrics_payload


# ─── Helpers ──────────────────────────────────────────────────────────────────

class _null_ctx:
    """Context manager nulo cuando MLflow no está disponible."""
    def __enter__(self): return None
    def __exit__(self, *_): pass


def _append_dqr(dqs: dict, metrics: dict) -> None:
    """Añade sección T-13 al DATA_QUALITY_REPORT.md."""
    DQR_PATH.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if DQR_PATH.exists() else "w"
    with open(DQR_PATH, mode, encoding="utf-8") as f:
        f.write(f"""
## T-13 — CorpusReal DQS Report

| Dimensión | Valor |
|---|---|
| DQS Total | {dqs['DQS']}/100 |
| N | {dqs['N']} |
| Completeness | {dqs['completeness']:.1f}% |
| Completeness sha256 | {dqs['completeness_sha256']:.1f}% |
| Completeness label | {dqs['completeness_label']:.1f}% |
| Validity | {dqs['validity']:.1f}% |
| Uniqueness | {dqs['uniqueness']:.1f}% |
| Duplicados sha256 | {dqs['duplicates']} |
| Labels inválidos | {dqs['invalid_labels']} |

### Métricas de campo (solo-ML, StratifiedKFold k=5)

| Métrica | Media | Std |
|---|---|---|
| AUC-ROC | {metrics['metrics']['auc_roc']:.4f} | — |
| AUC-PR | {metrics['metrics']['auc_pr']:.4f} | — |
| F1 | {metrics['metrics']['f1']:.4f} | — |
| FPR@TPR=90% | {metrics['metrics']['fpr_at_tpr90']:.4f} | — |
| TPR@FPR=1% | {metrics['metrics']['tpr_at_fpr1']:.4f} | — |

### Scaler Drift

| Campo | Corpus Real | Sintético (ref) |
|---|---|---|
| mean_post | {metrics['scaler_drift']['mean_post']:.4f} | {SYNTHETIC_MEAN_POST} |
| std_post | {metrics['scaler_drift']['std_post']:.4f} | {SYNTHETIC_STD_POST} |

> `data/test_set/X_test.npy` — **SINTETICO — no usar para métricas** de campo.

""")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="T-13 — Evaluación científica sobre CorpusReal (≥2000 PE con ground truth)."
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=CORPUS_DIR,
        help=f"Directorio con data/eval_real/manifest.csv y binarios. "
             f"Default: {CORPUS_DIR}",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Solo verificar DQS sin correr evaluación completa.",
    )
    args = parser.parse_args()

    corpus_dir = args.corpus.resolve()

    if not corpus_dir.exists():
        print(f"[SKIP] Corpus no encontrado en {corpus_dir}. "
              "Para adquirir el corpus ejecute: python tools/fetch_corpus.py --help",
              file=sys.stderr)
        sys.exit(0)

    if args.dry_run:
        dqs = compute_dqs(corpus_dir / MANIFEST_FNAME)
        print(json.dumps(dqs, indent=2))
        return

    evaluate(corpus_dir)


if __name__ == "__main__":
    main()
