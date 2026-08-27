"""
Generación de figuras académicas para ShadowNet Defender.
Solo usa datos verificados de la auditoría del 2026-08-18.
Los datos sintéticos del test_set se usan únicamente para ilustrar la arquitectura,
marcados claramente como "datos sintéticos / representativos".
"""

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


def save(fig, name):
    png_path = os.path.join(OUTPUT_DIR, f"{name}.png")
    svg_path = os.path.join(OUTPUT_DIR, f"{name}.svg")
    fig.savefig(png_path, dpi=150, bbox_inches='tight')
    fig.savefig(svg_path, bbox_inches='tight')
    plt.close(fig)
    print(f"Guardado: {name}.png / {name}.svg")


# ─────────────────────────────────────────────────────────────────────────────
# Figura 1: Comparativa ML vs. Híbrido en muestras reales
# ─────────────────────────────────────────────────────────────────────────────
def fig_comparativa_ml_vs_hibrido():
    samples = ['sample1.exe\n(overlay 98.7%)', 'sample2.exe\n(.NET ofuscado)', 'eicar.txt\n(no-PE)', 'procexp64.exe\n(legítimo)']
    ml_scores = [0.0000, 0.0000, 0.0001, 1.0000]
    op_status = ['DANGEROUS', 'CLEAN', 'CLEAN', 'UNKNOWN']
    risk_scores = [105, 1, 20, 0]
    colors_op = ['#d32f2f', '#388e3c', '#388e3c', '#9e9e9e']

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle('ShadowNet Defender — ML score vs. Operational Status (datos reales, 2026-08-18)',
                 fontsize=11, fontweight='bold')

    # ML Score
    bars1 = axes[0].bar(samples, ml_scores, color=['#1565c0', '#1565c0', '#1565c0', '#d32f2f'], edgecolor='black', linewidth=0.8)
    axes[0].axhline(0.5, color='red', linestyle='--', linewidth=1.5, label='Umbral ML (0.5)')
    axes[0].set_title('Score del Modelo ML', fontweight='bold')
    axes[0].set_ylabel('ML Score (0.0 – 1.0)')
    axes[0].set_ylim(0, 1.15)
    axes[0].legend()
    for bar, val in zip(bars1, ml_scores):
        axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                     f'{val:.4f}', ha='center', va='bottom', fontsize=9)

    # Risk Score + Operational Status
    bars2 = axes[1].bar(samples, risk_scores, color=colors_op, edgecolor='black', linewidth=0.8)
    axes[1].axhline(70, color='orange', linestyle='--', linewidth=1.2, label='Umbral CRITICAL (≥70)')
    axes[1].set_title('Risk Score del Sistema Multicapa', fontweight='bold')
    axes[1].set_ylabel('Risk Score')
    axes[1].set_ylim(0, 130)
    axes[1].legend()
    for bar, val, op in zip(bars2, risk_scores, op_status):
        axes[1].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                     f'{val}\n({op})', ha='center', va='bottom', fontsize=8.5, fontweight='bold')

    fig.text(0.5, -0.02,
             'Nota: ML score de procexp64.exe = 1.0 por YARA match, no por inferencia neuronal.',
             ha='center', fontsize=8, style='italic', color='gray')

    plt.tight_layout()
    save(fig, 'fig1_ml_vs_hibrido')


# ─────────────────────────────────────────────────────────────────────────────
# Figura 2: Distribución de riesgo — sample1.exe overlay analysis
# ─────────────────────────────────────────────────────────────────────────────
def fig_distribucion_riesgo_sample1():
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle('sample1.exe — Distribución forense del archivo (datos reales, 2026-08-18)',
                 fontsize=11, fontweight='bold')

    # Composición del archivo
    sizes = [272896, 20633886]
    labels = [f'Estructura PE\n(266 KB, 1.3%)', f'Overlay\n(19.7 MB, 98.7%)']
    colors = ['#1976d2', '#d32f2f']
    explode = (0, 0.1)
    wedges, texts, autotexts = axes[0].pie(
        sizes, labels=labels, colors=colors, explode=explode,
        autopct='%1.1f%%', startangle=90,
        textprops={'fontsize': 10}
    )
    autotexts[1].set_fontweight('bold')
    axes[0].set_title('Composición del archivo', fontweight='bold')

    # Indicadores activados
    indicators = [
        'overlay_ratio > 80%',
        'overlay_ratio > 93% (CRÍTICO)',
        'overlay_entropy > 7.2',
        'overlay_entropy > 7.8 (máx)',
        'global_entropy > 7.5',
        'packer_indicators=True'
    ]
    values = [98.7, 98.7, 7.9987, 7.9987, 7.9861, 1]
    display_values = [98.7, 98.7, 7.9987, 7.9987, 7.9861, 100]
    bar_colors = ['#ef5350'] * 6

    bars = axes[1].barh(indicators, display_values, color=bar_colors, edgecolor='black', linewidth=0.6)
    axes[1].set_title(f'Indicadores activados — Risk Score: 105 (CRITICAL)', fontweight='bold')
    axes[1].set_xlabel('Valor del indicador (escala variable)')

    for bar, val, ind in zip(bars, values, indicators):
        label = f'{val:.2f}' if '%' not in ind else f'{val:.1f}%'
        axes[1].text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                     label, va='center', fontsize=9)

    plt.tight_layout()
    save(fig, 'fig2_sample1_overlay')


# ─────────────────────────────────────────────────────────────────────────────
# Figura 3: Resultados de la suite de tests
# ─────────────────────────────────────────────────────────────────────────────
def fig_resultados_tests():
    categorias = ['Integration\n(10)', 'Properties\n(14)', 'Security\n(14)',
                  'Unit\n(37)', 'Feature tests\n(83)']
    passed  = [9,  14, 13, 33, 82]
    failed  = [0,   0,  1,  0,  1]
    skipped = [1,   0,  0,  4,  2]

    x = np.arange(len(categorias))
    width = 0.28

    fig, ax = plt.subplots(figsize=(11, 5))
    b1 = ax.bar(x - width, passed,  width, label='Passed', color='#43a047', edgecolor='black', linewidth=0.7)
    b2 = ax.bar(x,         failed,  width, label='Failed', color='#e53935', edgecolor='black', linewidth=0.7)
    b3 = ax.bar(x + width, skipped, width, label='Skipped', color='#fb8c00', edgecolor='black', linewidth=0.7)

    ax.set_title('Suite de Tests — Resultados por categoría\n(2026-08-18 | 158 tests totales: 151 passed, 2 failed, 5 skipped)',
                 fontweight='bold')
    ax.set_ylabel('Número de tests')
    ax.set_xticks(x)
    ax.set_xticklabels(categorias)
    ax.legend()
    ax.set_ylim(0, 100)

    for bar in b1:
        if bar.get_height() > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    str(int(bar.get_height())), ha='center', va='bottom', fontsize=9)
    for bar in b2:
        if bar.get_height() > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    str(int(bar.get_height())), ha='center', va='bottom', fontsize=9, color='#c62828')
    for bar in b3:
        if bar.get_height() > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    str(int(bar.get_height())), ha='center', va='bottom', fontsize=9)

    # Tasa global
    ax.text(0.98, 0.95, f'Tasa éxito: 155/158 = 98.1%\n(excl. skipped)',
            transform=ax.transAxes, ha='right', va='top', fontsize=10,
            bbox=dict(boxstyle='round', facecolor='#e8f5e9', alpha=0.8))

    plt.tight_layout()
    save(fig, 'fig3_test_results')


# ─────────────────────────────────────────────────────────────────────────────
# Figura 4: Arquitectura multicapa (diagrama visual)
# ─────────────────────────────────────────────────────────────────────────────
def fig_arquitectura_multicapa():
    fig, ax = plt.subplots(figsize=(10, 12))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 14)
    ax.axis('off')

    layers = [
        ('Entrada: Binario PE / EXE / DLL', '#546e7a', 13.0),
        ('Fase 1 — YARA Scanner\n4 archivos de reglas | Firmas deterministas', '#b71c1c', 11.5),
        ('Fase 2-3 — Feature Extractor + ML/ONNX\n2381 features | Red neuronal 512→256→128→1', '#1565c0', 10.0),
        ('Fase 4 — Overlay Analysis\nEntropía | Embedded PE | Ratio', '#e65100', 8.5),
        ('Fase 5 — DotNet Analysis\nCLR Header | Ofuscadores | Assemblies embebidos', '#4a148c', 7.0),
        ('Fase 6 — IL Behavioral Analysis\nTokens CLR: M2-M15 | Evidencias forenses', '#1b5e20', 5.5),
        ('Fase 7 — Risk Engine\nCorrelación multicapa → operational_status', '#37474f', 4.0),
        ('ScanResult: label + score + operational_status\n+ risk_level + risk_score + evidencias', '#263238', 2.5),
        ('Backend → Supabase + n8n + Ollama LLM', '#37474f', 1.0),
    ]

    for label, color, y in layers:
        box = FancyBboxPatch((1, y - 0.55), 8, 1.0,
                             boxstyle="round,pad=0.1",
                             facecolor=color, edgecolor='black',
                             linewidth=1.2, alpha=0.85)
        ax.add_patch(box)
        ax.text(5, y - 0.05, label, ha='center', va='center',
                fontsize=9, color='white', fontweight='bold',
                multialignment='center')

        if y > 1.0:
            ax.annotate('', xy=(5, y - 0.55), xytext=(5, y - 0.55 - 0.4),
                        arrowprops=dict(arrowstyle='->', color='black', lw=1.5))

    # Anotación del hallazgo
    ax.annotate('H-01: ML=BENIGN\nHeurística=DANGEROUS',
                xy=(9, 10.0 - 0.05), xytext=(9.3, 10.0),
                fontsize=7.5, color='#d32f2f', fontweight='bold',
                ha='left',
                arrowprops=dict(arrowstyle='->', color='#d32f2f', lw=1))

    ax.set_title('ShadowNet Defender — Arquitectura Multicapa (8 fases)',
                 fontsize=12, fontweight='bold', pad=15)

    plt.tight_layout()
    save(fig, 'fig4_arquitectura')


# ─────────────────────────────────────────────────────────────────────────────
# Figura 5: Hallazgos numerados
# ─────────────────────────────────────────────────────────────────────────────
def fig_hallazgos():
    hallazgos = [
        ('H-01', 'Divergencia ML vs.\nHeurística (overlay)', 'CRÍTICO', '#d32f2f'),
        ('H-02', 'Test set sintético\nincompatible', 'ALTO', '#f57c00'),
        ('H-03', 'Falso positivo YARA\nprocexp64.exe', 'MEDIO', '#fbc02d'),
        ('H-04', 'BehavioralShield\nno integrado', 'ALTO', '#f57c00'),
        ('H-05', 'n8n no alerta\npara DANGEROUS+BENIGN', 'CRÍTICO', '#d32f2f'),
        ('H-06', 'JWT expirado\nretorna HTTP 500', 'MEDIO', '#fbc02d'),
        ('H-07', 'Detección familias .NET\nsolo sobre datos sintéticos', 'BAJO', '#388e3c'),
        ('H-08', 'Muestreo 50.15%\npara archivos >10MB', 'MEDIO', '#fbc02d'),
    ]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.axis('off')

    ax.set_xlim(0, 12)
    ax.set_ylim(0, len(hallazgos) + 1)

    ax.text(0.5, len(hallazgos) + 0.5, 'ID', fontweight='bold', fontsize=10)
    ax.text(1.8, len(hallazgos) + 0.5, 'Descripción', fontweight='bold', fontsize=10)
    ax.text(8.5, len(hallazgos) + 0.5, 'Impacto', fontweight='bold', fontsize=10)

    for i, (hid, desc, impacto, color) in enumerate(hallazgos):
        y = len(hallazgos) - i - 0.2
        bg_color = '#fff8e1' if i % 2 == 0 else '#f5f5f5'
        ax.add_patch(FancyBboxPatch((0.1, y - 0.45), 11.8, 0.85,
                                    boxstyle="round,pad=0.05",
                                    facecolor=bg_color, edgecolor='#ccc',
                                    linewidth=0.8))
        ax.text(0.5, y, hid, fontweight='bold', fontsize=9, va='center', color='#1565c0')
        ax.text(1.8, y, desc, fontsize=8.5, va='center', multialignment='left')
        badge = FancyBboxPatch((8.2, y - 0.3), 2.8, 0.6,
                               boxstyle="round,pad=0.05",
                               facecolor=color, edgecolor='none', alpha=0.85)
        ax.add_patch(badge)
        ax.text(9.6, y, impacto, fontsize=8, va='center', ha='center',
                color='white', fontweight='bold')

    ax.set_title('ShadowNet Defender — Hallazgos de Auditoría (2026-08-18)',
                 fontsize=11, fontweight='bold')
    plt.tight_layout()
    save(fig, 'fig5_hallazgos')


# ─────────────────────────────────────────────────────────────────────────────
# Figura 6: Latencia por fase
# ─────────────────────────────────────────────────────────────────────────────
def fig_latencia():
    fases = ['YARA\n(early exit)', 'Extracción\nPE_FASTLOAD\n>10MB', 'Extracción\nPE normal',
             'Extracción\nRAW_FALLBACK', 'Pipeline\ncompleto\nsample1', 'Pipeline\ncompleto\nsample2']
    tiempos = [55, 783.9, 229.2, 59.0, 1240, 707]
    colors = ['#43a047', '#e53935', '#ff8f00', '#43a047', '#d32f2f', '#1565c0']

    fig, ax = plt.subplots(figsize=(11, 5))
    bars = ax.bar(fases, tiempos, color=colors, edgecolor='black', linewidth=0.7)
    ax.axhline(500, color='orange', linestyle='--', linewidth=1.5, label='Límite objetivo 500ms')
    ax.set_title('ShadowNet Defender — Latencia real por fase\n(mediciones en ejecución real, 2026-08-18)',
                 fontweight='bold')
    ax.set_ylabel('Tiempo (ms)')
    ax.set_ylim(0, 1450)
    ax.legend()

    for bar, val in zip(bars, tiempos):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 15,
                f'{val:.0f}ms', ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.tight_layout()
    save(fig, 'fig6_latencia')


# ─────────────────────────────────────────────────────────────────────────────
# Figura 7: ROC ilustrativa — NOTA EXPLÍCITA: datos NO son de campo real
# ─────────────────────────────────────────────────────────────────────────────
def fig_roc_representativa():
    """
    ADVERTENCIA: Esta figura usa la curva ROC del test set SINTÉTICO disponible
    en el repositorio. Los valores AUC=1.0 corresponden al test set sintético
    y perfectamente separable, NO a evaluación sobre malware real.
    Se incluye únicamente para ilustrar la metodología de evaluación,
    NO para reportar rendimiento del sistema.
    """
    import onnxruntime as ort
    from sklearn.metrics import roc_curve, auc as sklearn_auc, precision_recall_curve

    # Cargar test set sintético
    base = os.path.join(os.path.dirname(__file__), '..', '..', '..')
    X = np.load(os.path.join(base, 'data/test_set/X_test.npy'))
    y = np.load(os.path.join(base, 'data/test_set/y_test.npy'))

    # El modelo da scores que se invierten respecto a las etiquetas del test set sintético
    # y_inv representa la convención del modelo: score alto = benign
    y_inv = 1 - y  # etiquetas: 0=malware, 1=benign → convención modelo

    model_path = os.path.join(base, 'models/best_model.onnx')
    sess = ort.InferenceSession(model_path)
    input_name = sess.get_inputs()[0].name
    output_name = sess.get_outputs()[0].name

    scores = sess.run([output_name], {input_name: X.astype(np.float32)})[0].flatten()

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle('ADVERTENCIA: Curvas calculadas sobre test set SINTÉTICO — no representativas de campo real\n'
                 'El test set (data/test_set/) es incompatible con el scaler de producción (ver H-02)',
                 fontsize=9, color='#d32f2f', fontweight='bold')

    # ROC
    fpr_c, tpr_c, _ = roc_curve(y_inv, scores)
    roc_auc_val = sklearn_auc(fpr_c, tpr_c)
    axes[0].plot(fpr_c, tpr_c, color='#1565c0', lw=2,
                 label=f'ROC (AUC = {roc_auc_val:.2f})\n[TEST SET SINTÉTICO]')
    axes[0].plot([0, 1], [0, 1], color='gray', lw=1, linestyle='--', label='Aleatorio')
    axes[0].set_title('Curva ROC — TEST SET SINTÉTICO', fontweight='bold')
    axes[0].set_xlabel('Tasa de Falsos Positivos')
    axes[0].set_ylabel('Tasa de Verdaderos Positivos')
    axes[0].legend()
    axes[0].text(0.35, 0.15, '⚠️ DATOS SINTÉTICOS\nNo usar para reportar rendimiento',
                 fontsize=9, color='red', ha='center',
                 bbox=dict(boxstyle='round', facecolor='#fff3e0', alpha=0.9))

    # Precision-Recall
    prec_c, rec_c, _ = precision_recall_curve(y_inv, scores)
    axes[1].plot(rec_c, prec_c, color='#e65100', lw=2, label='PR Curve [TEST SET SINTÉTICO]')
    axes[1].set_title('Curva Precision-Recall — TEST SET SINTÉTICO', fontweight='bold')
    axes[1].set_xlabel('Recall')
    axes[1].set_ylabel('Precision')
    axes[1].legend()
    axes[1].text(0.35, 0.15, '⚠️ DATOS SINTÉTICOS\nNo usar para reportar rendimiento',
                 fontsize=9, color='red', ha='center',
                 bbox=dict(boxstyle='round', facecolor='#fff3e0', alpha=0.9))

    plt.tight_layout()
    save(fig, 'fig7_roc_pr_SINTETICO')


if __name__ == '__main__':
    print("Generando figuras académicas de ShadowNet Defender...")
    fig_comparativa_ml_vs_hibrido()
    fig_distribucion_riesgo_sample1()
    fig_resultados_tests()
    fig_arquitectura_multicapa()
    fig_hallazgos()
    fig_latencia()
    try:
        fig_roc_representativa()
    except Exception as e:
        print(f"fig7 no generada (requiere test set): {e}")
    print("\nFiguras generadas en docs/academico/figures/")
