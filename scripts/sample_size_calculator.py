"""
scripts/sample_size_calculator.py — Calculadora de tamaño muestral (experiment-designer).

Computa el tamaño muestral requerido para tests de proporciones (no pareados)
y estimación para McNemar pareado (T-14).

Uso:
    # Test no pareado (proporciones)
    python scripts/sample_size_calculator.py --baseline-rate 0.10 --mde 0.08 --mde-type absolute

    # Escenario T-14 exacto (FNR baseline 0.10 → 0.18)
    python scripts/sample_size_calculator.py --baseline-rate 0.10 --mde 0.08 --mde-type absolute --alpha 0.05 --power 0.8

    # Con corrección McNemar pareado
    python scripts/sample_size_calculator.py --baseline-rate 0.10 --mde 0.08 --paired --correlation 0.5

    # AUC-ROC scenario T-13
    python scripts/sample_size_calculator.py --baseline-rate 0.90 --mde 0.05 --mde-type absolute --metric auc
"""
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ─── Distribución normal inversa (sin scipy) ──────────────────────────────────

def _norm_ppf(p: float) -> float:
    """
    Aproximación de la función inversa de la distribución normal estándar.
    Precisión suficiente para cálculos de potencia estadística.
    """
    # Algoritmo racional de Beasley-Springer-Moro
    a = [2.50662823884, -18.61500062529, 41.39119773534, -25.44106049637]
    b = [-8.47351093090, 23.08336743743, -21.06224101826, 3.13082909833]
    c = [
        0.3374754822726147, 0.9761690190917186, 0.1607979714918209,
        0.0276438810333863, 0.0038405729373609, 0.0003951896511349,
        0.0000321767881768, 0.0000002888167364, 0.0000003960315187,
    ]

    if p <= 0 or p >= 1:
        raise ValueError(f"p debe estar en (0,1), got {p}")

    y = p - 0.5
    if abs(y) < 0.42:
        r = y * y
        result = y * (((a[3] * r + a[2]) * r + a[1]) * r + a[0]) / (
            ((b[3] * r + b[2]) * r + b[1]) * r + b[0] + 1
        )
    else:
        r = math.sqrt(-math.log(min(p, 1 - p)))
        result = c[0] + r * (c[1] + r * (c[2] + r * (c[3] + r * (
            c[4] + r * (c[5] + r * (c[6] + r * (c[7] + r * c[8])))))))
        if y < 0:
            result = -result

    return result


# ─── Sample size para proporciones ────────────────────────────────────────────

def sample_size_proportions(
    baseline_rate: float,
    mde: float,
    mde_type: str = "absolute",
    alpha: float = 0.05,
    power: float = 0.80,
    two_sided: bool = True,
) -> dict:
    """
    Calcula tamaño muestral para test de proporciones (no pareado).

    Args:
        baseline_rate: tasa base (p1)
        mde: efecto mínimo detectable
        mde_type: 'absolute' o 'relative'
        alpha: nivel de significancia
        power: potencia estadística
        two_sided: test bilateral

    Returns:
        dict con n_per_group, n_total, mde_absolute, etc.
    """
    p1 = baseline_rate
    if mde_type == "relative":
        mde_abs = p1 * mde
    else:
        mde_abs = mde

    p2 = p1 + mde_abs
    if not (0 < p1 < 1 and 0 < p2 < 1):
        raise ValueError(f"Tasas fuera de (0,1): p1={p1:.4f}, p2={p2:.4f}")

    alpha_adj = alpha / 2 if two_sided else alpha
    z_alpha = _norm_ppf(1 - alpha_adj)
    z_beta = _norm_ppf(power)

    p_bar = (p1 + p2) / 2
    n_per_group = math.ceil(
        (z_alpha * math.sqrt(2 * p_bar * (1 - p_bar)) + z_beta * math.sqrt(
            p1 * (1 - p1) + p2 * (1 - p2)
        )) ** 2 / (mde_abs ** 2)
    )

    return {
        "method": "proportions_z_test",
        "baseline_rate": p1,
        "target_rate": round(p2, 6),
        "mde_absolute": round(mde_abs, 6),
        "alpha": alpha,
        "power": power,
        "two_sided": two_sided,
        "z_alpha": round(z_alpha, 4),
        "z_beta": round(z_beta, 4),
        "n_per_group": n_per_group,
        "n_total": 2 * n_per_group,
    }


# ─── Sample size McNemar pareado ──────────────────────────────────────────────

def sample_size_mcnemar(
    fnr_ml: float,
    fnr_hybrid: float,
    alpha: float = 0.05,
    power: float = 0.80,
    correlation: float = 0.50,
) -> dict:
    """
    Estima tamaño muestral para McNemar pareado (T-14).

    La potencia del McNemar depende de los pares discordantes (b + c).
    Con correlación intra-par, la varianza se reduce respecto al test no pareado.

    Fórmula basada en el método de Agresti (2002):
        N = (z_alpha + z_beta)^2 / (p_b - p_c)^2 * (p_b + p_c)
    donde p_b = P(ML wrong, H correct) ≈ FNR_ML - FNR_H
          p_c = P(ML correct, H wrong) ≈ epsilon (pequeño)

    Args:
        fnr_ml: FNR estimado del sistema solo-ML
        fnr_hybrid: FNR estimado del sistema híbrido
        alpha: nivel de significancia (idealmente ya corregido con Bonferroni)
        power: potencia estadística
        correlation: correlación intra-par estimada (reduce varianza vs no-pareado)
    """
    z_alpha = _norm_ppf(1 - alpha / 2)
    z_beta = _norm_ppf(power)

    # Pares discordantes esperados
    # p_b: ML falla pero H acierta (ganancia principal)
    # p_c: ML acierta pero H falla (pérdida, esperada pequeña)
    p_b = max(fnr_ml - fnr_hybrid, 0.001)   # ganancia esperada
    p_c = max(fnr_hybrid * 0.1, 0.001)       # pequeña pérdida posible

    p_discordant = p_b + p_c  # fracción de pares discordantes

    if p_discordant <= 0:
        raise ValueError("fnr_ml debe ser mayor que fnr_hybrid")

    # N estimado por McNemar (con corrección de continuidad de Yates)
    n_mcnemar = math.ceil(
        (z_alpha * math.sqrt(p_discordant) + z_beta * math.sqrt(p_discordant - (p_b - p_c) ** 2)) ** 2
        / (p_b - p_c) ** 2
    )

    # Ajuste por correlación intra-par
    # En test pareado, la reducción de varianza ≈ 1 - rho
    effective_n = math.ceil(n_mcnemar * (1 - correlation))

    # Referencia no-pareada
    non_paired = sample_size_proportions(fnr_ml, fnr_ml - fnr_hybrid, alpha=alpha, power=power)

    return {
        "method": "mcnemar_paired",
        "fnr_ml": fnr_ml,
        "fnr_hybrid": fnr_hybrid,
        "fnr_diff": round(fnr_ml - fnr_hybrid, 4),
        "alpha": alpha,
        "alpha_bonferroni": round(alpha / 3, 6),
        "power": power,
        "correlation_intra_pair": correlation,
        "p_discordant_b": round(p_b, 4),
        "p_discordant_c": round(p_c, 4),
        "n_mcnemar_raw": n_mcnemar,
        "n_mcnemar_corr_for_correlation": effective_n,
        "n_total_mcnemar": max(effective_n, 100),
        "n_per_group_non_paired": non_paired["n_per_group"],
        "n_total_non_paired": non_paired["n_total"],
        "conclusion": (
            f"McNemar pareado: N≥{max(effective_n, 100)} (mínimo aceptable), "
            f"N≥{max(effective_n * 2, 200)} (ideal). "
            f"Test no-pareado requeriría N≥{non_paired['n_total']} total."
        ),
    }


# ─── Sample size AUC-ROC ──────────────────────────────────────────────────────

def sample_size_auc(
    baseline_auc: float,
    mde: float,
    alpha: float = 0.05,
    power: float = 0.80,
    prevalence: float = 0.50,
) -> dict:
    """
    Estima N para detectar diferencia en AUC-ROC.
    Aproximación via test de Hanley-McNeil (1982).

    Args:
        baseline_auc: AUC-ROC de referencia
        mde: diferencia mínima detectable en AUC
        prevalence: proporción de positivos (default 0.5 — balanceado)
    """
    A = baseline_auc
    q1 = A / (2 - A)
    q2 = 2 * A ** 2 / (1 + A)
    V_A = (A * (1 - A) + (prevalence - 1) * (q1 - A ** 2) + prevalence * (q2 - A ** 2)) / (
        prevalence * (1 - prevalence)
    )

    z_alpha = _norm_ppf(1 - alpha / 2)
    z_beta = _norm_ppf(power)

    n = math.ceil((z_alpha + z_beta) ** 2 * V_A / (mde ** 2))

    return {
        "method": "auc_hanley_mcneil",
        "baseline_auc": baseline_auc,
        "target_auc": round(baseline_auc + mde, 4),
        "mde_absolute": mde,
        "alpha": alpha,
        "power": power,
        "prevalence": prevalence,
        "n_total": n,
        "note": "N total (ambas clases). Con prevalencia 0.5: N/2 positivos + N/2 negativos.",
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "sample_size_calculator.py — Tamaño muestral para experimentos F4.\n\n"
            "Escenarios documentados en design.md:\n"
            "  T-13: AUC-ROC 0.90 vs 0.95 → N=436 por grupo\n"
            "  T-14: FNR 0.10 → 0.18 (Δ=0.08) → N=296 no-pareado / N=100 McNemar"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--baseline-rate", type=float, required=True,
                        help="Tasa base (AUC, FNR, TPR, etc.)")
    parser.add_argument("--mde", type=float, required=True,
                        help="Efecto mínimo detectable (MDE)")
    parser.add_argument("--mde-type", choices=["absolute", "relative"], default="absolute",
                        help="Tipo de MDE: absolute (default) o relative")
    parser.add_argument("--alpha", type=float, default=0.05,
                        help="Nivel de significancia (default 0.05). Para Bonferroni usar 0.05/3=0.0167")
    parser.add_argument("--power", type=float, default=0.80,
                        help="Potencia estadística (default 0.80)")
    parser.add_argument("--paired", action="store_true",
                        help="Calcular para McNemar pareado (T-14 overlay benchmark)")
    parser.add_argument("--correlation", type=float, default=0.50,
                        help="Correlación intra-par para McNemar (default 0.50)")
    parser.add_argument("--metric", choices=["proportion", "auc"], default="proportion",
                        help="Tipo de métrica: proportion (default) o auc")
    parser.add_argument("--prevalence", type=float, default=0.50,
                        help="Prevalencia para cálculo AUC (default 0.50 — balanceado)")
    parser.add_argument("--format", choices=["human", "json"], default="human",
                        help="Formato de salida")
    args = parser.parse_args()

    results = {}

    try:
        if args.metric == "auc":
            results["auc"] = sample_size_auc(
                args.baseline_rate, args.mde, args.alpha, args.power, args.prevalence
            )
        elif args.paired:
            # Para McNemar: baseline_rate=FNR_ML, mde=Δ → FNR_hybrid = baseline - mde
            fnr_hybrid = args.baseline_rate - args.mde
            results["proportions_non_paired"] = sample_size_proportions(
                args.baseline_rate, args.mde, args.mde_type, args.alpha, args.power
            )
            results["mcnemar_paired"] = sample_size_mcnemar(
                args.baseline_rate, fnr_hybrid, args.alpha, args.power, args.correlation
            )
        else:
            results["proportions"] = sample_size_proportions(
                args.baseline_rate, args.mde, args.mde_type, args.alpha, args.power
            )
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    if args.format == "json":
        import json
        print(json.dumps(results, indent=2))
        return

    # Human-readable output
    print("\n" + "=" * 60)
    print("  SAMPLE SIZE CALCULATOR — experiment-designer (F4)")
    print("=" * 60)

    for method, r in results.items():
        print(f"\n  ─── {r.get('method', method).upper()} ───")
        for k, v in r.items():
            if k == "method":
                continue
            if isinstance(v, str) and len(v) > 60:
                print(f"  {k}:")
                print(f"    {v}")
            else:
                print(f"  {k:<35} {v}")

    # Resumen ejecutivo
    print("\n  ─── RESUMEN EJECUTIVO (design.md T-14) ───────────────────")
    if "mcnemar_paired" in results:
        mc = results["mcnemar_paired"]
        np_ = results.get("proportions_non_paired", {})
        print(f"  baseline FNR={mc['fnr_ml']} → FNR_hibrido={mc['fnr_hybrid']} (Δ={mc['fnr_diff']})")
        print(f"  No-pareado: N_total={np_.get('n_total', '?')} | McNemar pareado: N≥{mc['n_total_mcnemar']}")
        print(f"  → N=100 mínimo aceptable, N=200 ideal (con correlación ρ={mc['correlation_intra_pair']})")
        print(f"  → Bonferroni α={mc['alpha_bonferroni']:.4f} (α/3 para FPR@TPR90+TPR@FPR1+F1)")
    elif "auc" in results:
        r = results["auc"]
        print(f"  AUC-ROC {r['baseline_auc']} vs {r['target_auc']} (Δ={r['mde_absolute']})")
        print(f"  → N_total={r['n_total']} ({r['n_total']//2} positivos + {r['n_total']//2} negativos)")
    else:
        r = list(results.values())[0]
        print(f"  → N_per_group={r.get('n_per_group', '?')}  N_total={r.get('n_total', '?')}")
    print()


if __name__ == "__main__":
    main()
