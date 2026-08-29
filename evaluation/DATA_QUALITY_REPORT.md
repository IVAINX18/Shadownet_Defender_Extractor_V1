# Data Quality Report — ShadowNet Defender F4

> Generado automáticamente por `evaluation/evaluate_real_corpus.py` (T-13) y
> `evaluation/benchmark_overlay.py` (T-14).
>
> Este archivo se actualiza cada vez que se ejecuta una evaluación con corpus real.

---

## Estado actual

| Corpus | Estado | DQS | N |
|---|---|---|---|
| CorpusReal (`data/eval_real/`) | ⏳ Pendiente adquisición | — | — |
| CorpusOverlay (`samples/overlay_corpus/`) | ⏳ Pendiente adquisición | — | — |

---

## DQS Score Reference

El Data Quality Score (DQS) usa la siguiente ponderación:

| Dimensión | Peso | Descripción |
|---|---|---|
| Completeness | 30% | sha256, label, source no nulos |
| Consistency | 25% | columnas requeridas presentes |
| Validity | 20% | label ∈ {0,1}, sha256 hex 64 chars |
| Uniqueness | 15% | 0 duplicados sha256 |
| Timeliness | 10% | vt_report presente |

**Umbrales**: DQS ≥ 85 → Production-ready · ≥ 70 → Acceptable · < 70 → Rechazado

---

## Missingness Policy (data-quality-auditor)

- `overlay_ratio` nulo para PE sin overlay → **MCAR** (Missing Completely At Random).
  No imputar. Documentar null% separado. PE sin overlay es esperado en corpus benigno.
- `overlay_entropy` nulo correlacionado con `overlay_ratio=0` → **MAR** (Missing At Random
  dado ratio). No imputar con media — sesgo estadístico si null% > 30%.

---

<!-- SECCIONES AUTOGENERADAS — NO EDITAR MANUALMENTE -->
<!-- Las secciones T-13 y T-14 son añadidas por evaluate_real_corpus.py y benchmark_overlay.py -->
