"""
scripts/data_profiler.py — Perfilado de calidad de datos (data-quality-auditor).

Calcula DQS (Data Quality Score 0-100) sobre manifest.csv del corpus F4.
Aplicable a CorpusReal (T-13) y CorpusOverlay (T-14).

Uso:
    python scripts/data_profiler.py --file data/eval_real/manifest.csv
    python scripts/data_profiler.py --file samples/overlay_corpus/manifest.csv
    python scripts/data_profiler.py --file data/eval_real/manifest.csv --format json
    python scripts/data_profiler.py --file data/eval_real/manifest.csv --monitor
    python scripts/data_profiler.py --file data.csv --columns sha256,label,source
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ─── Constantes DQS ───────────────────────────────────────────────────────────

DQS_WEIGHTS = {
    "completeness": 0.30,
    "consistency": 0.25,
    "validity": 0.20,
    "uniqueness": 0.15,
    "timeliness": 0.10,
}

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Columnas requeridas por corpus
REQUIRED_COLS_REAL = {"sha256", "label", "source"}
REQUIRED_COLS_OVERLAY = {"sha256", "overlay_ratio", "overlay_entropy", "vt_report"}

# ─── Perfilado por columna ─────────────────────────────────────────────────────

def profile_column(values: list[str], col_name: str) -> dict:
    """Perfil completo de una columna: nulos, cardinalidad, distribución, validez."""
    N = len(values)
    if N == 0:
        return {"N": 0, "null_pct": 100.0}

    null_vals = {"", "null", "none", "n/a", "na", "nan", "-"}
    nulls = sum(1 for v in values if v.strip().lower() in null_vals)
    non_null = [v.strip() for v in values if v.strip().lower() not in null_vals]

    cardinality = len(set(non_null))
    top_values = dict(Counter(non_null).most_common(5))

    # Intentar parsear como numérico
    numeric_vals = []
    for v in non_null:
        try:
            numeric_vals.append(float(v))
        except ValueError:
            pass

    profile: dict[str, Any] = {
        "N": N,
        "null_count": nulls,
        "null_pct": round(100 * nulls / N, 2),
        "cardinality": cardinality,
        "top_values": top_values,
    }

    if numeric_vals:
        try:
            import statistics
            profile["min"] = round(min(numeric_vals), 4)
            profile["max"] = round(max(numeric_vals), 4)
            profile["mean"] = round(statistics.mean(numeric_vals), 4)
            profile["std"] = round(statistics.stdev(numeric_vals), 4) if len(numeric_vals) > 1 else 0.0
        except Exception:
            pass

    # Validaciones por columna conocida
    issues = []
    if col_name == "sha256":
        invalid = sum(1 for v in non_null if not SHA256_RE.match(v))
        profile["invalid_sha256"] = invalid
        if invalid > 0:
            issues.append(f"{invalid} hashes SHA256 con formato inválido (esperado hex 64 chars)")
    elif col_name == "label":
        invalid = sum(1 for v in non_null if v not in ("0", "1"))
        profile["invalid_labels"] = invalid
        if invalid > 0:
            issues.append(f"{invalid} labels inválidos (esperado 0 o 1, got: {set(non_null) - {'0','1'}})")
    elif col_name == "overlay_ratio":
        try:
            out_of_range = sum(1 for v in numeric_vals if not (0.0 <= v <= 1.0))
            if out_of_range:
                issues.append(f"{out_of_range} valores overlay_ratio fuera de [0, 1]")
        except Exception:
            pass
    elif col_name == "overlay_entropy":
        try:
            out_of_range = sum(1 for v in numeric_vals if not (0.0 <= v <= 8.0))
            if out_of_range:
                issues.append(f"{out_of_range} valores overlay_entropy fuera de [0, 8]")
        except Exception:
            pass

    # Missingness policy
    if col_name in ("overlay_ratio", "overlay_entropy") and nulls > 0:
        if col_name == "overlay_ratio":
            issues.append(
                f"MCAR: {nulls} nulos esperados para PE sin overlay — no imputar. "
                f"Documentar null%={profile['null_pct']:.1f}% por separado."
            )
        else:
            issues.append(
                f"MAR: {nulls} nulos correlacionados con overlay_ratio=0 — no imputar con media. "
                f"null%={profile['null_pct']:.1f}%"
            )

    if issues:
        profile["issues"] = issues

    return profile


# ─── DQS ──────────────────────────────────────────────────────────────────────

def compute_dqs_full(rows: list[dict], fieldnames: list[str]) -> dict:
    """DQS completo con breakdown por dimensión."""
    N = len(rows)
    if N == 0:
        return {"DQS": 0, "N": 0}

    fields = set(fieldnames)

    # ── Completeness ──────────────────────────────────────────────────────────
    null_vals_set = {"", "null", "none", "n/a", "na", "nan", "-"}
    critical_cols = {"sha256", "label"} if "label" in fields else {"sha256"}
    completeness_per_col = {}
    for col in critical_cols:
        if col in fields:
            nulls = sum(1 for r in rows if r.get(col, "").strip().lower() in null_vals_set)
            completeness_per_col[col] = 100 * (1 - nulls / N)
    completeness = sum(completeness_per_col.values()) / max(len(completeness_per_col), 1)

    # ── Consistency ───────────────────────────────────────────────────────────
    # Required cols present + no mixed types in numeric columns
    detected_required = REQUIRED_COLS_REAL if "label" in fields else REQUIRED_COLS_OVERLAY
    missing_req = detected_required - fields
    consistency = 100.0 if not missing_req else max(0.0, 100.0 - len(missing_req) * 20)

    # ── Validity ──────────────────────────────────────────────────────────────
    validity_checks = []
    if "sha256" in fields:
        invalid_sha = sum(1 for r in rows if not SHA256_RE.match(r.get("sha256", "").strip()))
        validity_checks.append(100 * (1 - invalid_sha / N))
    if "label" in fields:
        invalid_label = sum(1 for r in rows if r.get("label", "").strip() not in ("0", "1"))
        validity_checks.append(100 * (1 - invalid_label / N))
    if "overlay_ratio" in fields:
        bad_ratio = 0
        for r in rows:
            v = r.get("overlay_ratio", "").strip()
            if v:
                try:
                    f = float(v)
                    if not (0.0 <= f <= 1.0):
                        bad_ratio += 1
                except ValueError:
                    bad_ratio += 1
        validity_checks.append(100 * (1 - bad_ratio / N))
    validity = sum(validity_checks) / max(len(validity_checks), 1)

    # ── Uniqueness ────────────────────────────────────────────────────────────
    sha256s = [r.get("sha256", "").strip().lower() for r in rows if r.get("sha256", "").strip()]
    duplicates = len(sha256s) - len(set(sha256s))
    uniqueness = 100 * (1 - duplicates / N)

    # ── Timeliness ────────────────────────────────────────────────────────────
    timeliness = 100.0 if "vt_report" in fields else 50.0

    dqs = (
        DQS_WEIGHTS["completeness"] * completeness
        + DQS_WEIGHTS["consistency"] * consistency
        + DQS_WEIGHTS["validity"] * validity
        + DQS_WEIGHTS["uniqueness"] * uniqueness
        + DQS_WEIGHTS["timeliness"] * timeliness
    )

    tier = "🟢 Production-ready" if dqs >= 85 else ("🟡 Usable with caveats" if dqs >= 65 else "🔴 Remediation required")

    return {
        "DQS": round(dqs, 2),
        "tier": tier,
        "N": N,
        "dimensions": {
            "completeness": round(completeness, 2),
            "consistency": round(consistency, 2),
            "validity": round(validity, 2),
            "uniqueness": round(uniqueness, 2),
            "timeliness": round(timeliness, 2),
        },
        "completeness_per_col": {k: round(v, 2) for k, v in completeness_per_col.items()},
        "duplicates_sha256": duplicates,
        "missing_required_cols": list(missing_req),
    }


# ─── Top issues rankeados ─────────────────────────────────────────────────────

def rank_issues(col_profiles: dict[str, dict], dqs_report: dict) -> list[str]:
    """Rankea issues por severidad × amplitud."""
    issues = []

    # Missing required cols — crítico
    for col in dqs_report.get("missing_required_cols", []):
        issues.append(f"[CRITICAL] Columna requerida ausente: '{col}'")

    # Duplicados sha256 — crítico
    dups = dqs_report.get("duplicates_sha256", 0)
    if dups > 0:
        issues.append(f"[CRITICAL] {dups} duplicados de sha256 (Uniqueness < 100%)")

    # Por columna
    for col, prof in col_profiles.items():
        null_pct = prof.get("null_pct", 0)
        for issue in prof.get("issues", []):
            severity = "WARN" if null_pct < 30 else "ERROR"
            issues.append(f"[{severity}] {col}: {issue}")
        if null_pct > 30 and col not in ("overlay_ratio", "overlay_entropy"):
            issues.append(f"[ERROR] {col}: null%={null_pct:.1f}% > 30% — revisar fuente de datos")
        elif null_pct > 10 and col not in ("overlay_ratio", "overlay_entropy"):
            issues.append(f"[WARN] {col}: null%={null_pct:.1f}% > 10% — imputar con indicador")

    return issues


# ─── Formato de salida ────────────────────────────────────────────────────────

def print_report(file_path: Path, col_profiles: dict, dqs: dict, issues: list) -> None:
    """Imprime reporte human-readable."""
    dqs_val = dqs["DQS"]
    tier = dqs["tier"]

    print("\n" + "=" * 70)
    print(f"  DATA QUALITY REPORT — {file_path.name}")
    print("=" * 70)
    print(f"\n  ┌─ BOTTOM LINE ────────────────────────────────────────────────┐")
    print(f"  │  DQS: {dqs_val:.1f}/100  {tier}")
    print(f"  │  N: {dqs['N']} filas  │  Columnas: {', '.join(col_profiles.keys())}")
    print(f"  └──────────────────────────────────────────────────────────────┘\n")

    print("  DIMENSIONES:")
    for dim, weight in DQS_WEIGHTS.items():
        score = dqs["dimensions"][dim]
        bar = "█" * int(score / 10) + "░" * (10 - int(score / 10))
        print(f"    {dim:15s} {bar} {score:5.1f}%  (peso {int(weight*100)}%)")

    print("\n  POR COLUMNA:")
    for col, prof in col_profiles.items():
        null_pct = prof.get("null_pct", 0.0)
        card = prof.get("cardinality", 0)
        indicator = "✅" if null_pct < 5 else ("⚠️ " if null_pct < 30 else "❌")
        print(f"    {indicator} {col:<22} null={null_pct:5.1f}%  cardinality={card}")
        if "min" in prof:
            print(f"       min={prof['min']}  max={prof['max']}  mean={prof['mean']}  std={prof['std']}")

    if issues:
        print(f"\n  ISSUES ({len(issues)} encontrados, rankeados por severidad):")
        for i, issue in enumerate(issues, 1):
            print(f"    {i:2d}. {issue}")
    else:
        print("\n  ✅ Sin issues detectados.")

    print("\n  HOW TO ACT:")
    if dqs_val >= 85:
        print("    → Corpus listo para evaluación. Ejecutar evaluate_real_corpus.py / benchmark_overlay.py.")
    elif dqs_val >= 65:
        print("    → Documentar caveats antes de usar. Verificar columnas con issues.")
    else:
        print("    → REMEDIAR antes de usar. Ver issues arriba por orden de prioridad.")
    print()


def print_monitor(dqs: dict, col_profiles: dict) -> None:
    """Imprime umbrales de monitoreo en formato config."""
    print("\n# data_profiler monitoring thresholds")
    print(f"dqs_min: {max(dqs['DQS'] - 5, 70)}")
    print("column_thresholds:")
    for col, prof in col_profiles.items():
        null_pct = prof.get("null_pct", 0)
        print(f"  {col}:")
        print(f"    max_null_pct: {max(null_pct + 5, 5):.1f}")
        if "min" in prof:
            print(f"    min_value: {prof['min']}")
            print(f"    max_value: {prof['max']}")


# ─── CLI principal ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "data_profiler.py — Perfilado DQS para corpus F4 (data-quality-auditor).\n"
            "Calcula Data Quality Score (0-100) sobre manifest.csv."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--file", required=True, type=Path, help="Ruta al manifest.csv a perfilar.")
    parser.add_argument(
        "--columns",
        default="",
        help="Columnas a perfilar (separadas por coma). Default: todas.",
    )
    parser.add_argument(
        "--format",
        choices=["human", "json"],
        default="human",
        help="Formato de salida: human (default) o json.",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Imprimir umbrales de monitoreo en formato config.",
    )
    args = parser.parse_args()

    file_path: Path = args.file.resolve()
    if not file_path.exists():
        print(f"[ERROR] Archivo no encontrado: {file_path}", file=sys.stderr)
        sys.exit(1)

    # Leer CSV
    rows = []
    fieldnames = []
    with open(file_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        for r in reader:
            rows.append(r)

    # Filtrar columnas si se especificó
    selected_cols = [c.strip() for c in args.columns.split(",") if c.strip()] or fieldnames

    # Perfil por columna
    col_profiles: dict[str, dict] = {}
    for col in selected_cols:
        if col in fieldnames:
            values = [r.get(col, "") for r in rows]
            col_profiles[col] = profile_column(values, col)

    # DQS global
    dqs = compute_dqs_full(rows, fieldnames)

    # Issues rankeados
    issues = rank_issues(col_profiles, dqs)

    if args.format == "json":
        output = {
            "file": str(file_path),
            "dqs": dqs,
            "columns": col_profiles,
            "issues": issues,
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    if args.monitor:
        print_monitor(dqs, col_profiles)
        return

    print_report(file_path, col_profiles, dqs, issues)

    # Exit code basado en DQS
    if dqs["DQS"] < 65:
        sys.exit(2)  # Remediation required
    elif dqs["DQS"] < 85:
        sys.exit(1)  # Usable with caveats
    # 0 = Production-ready


if __name__ == "__main__":
    main()
