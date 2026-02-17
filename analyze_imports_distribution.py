#!/usr/bin/env python3
"""
Análisis Comparativo: Distribución de Imports
Malware vs Software Legítimo

Este script compara las distribuciones de imports entre archivos
maliciosos y benignos usando el feature hashing implementado.

OBJETIVO:
Demostrar que aunque el feature hashing introduce colisiones,
las distribuciones globales son suficientemente diferentes para
permitir discriminación por modelos ML.

AUTOR: ShadowNet Defender Team
"""

import numpy as np
import sys
import os
from pathlib import Path

# Añadir ruta del proyecto
sys.path.insert(0, str(Path(__file__).parent))

from core.features.imports import ImportsFeatureBlock
import pefile

# Intentar importar matplotlib, pero no requerir
try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("⚠️  matplotlib no disponible, gráficos deshabilitados")


def analyze_file(file_path: str, label: str = "Unknown"):
    """
    Analiza un archivo PE y extrae estadísticas de imports.
    
    Args:
        file_path: Ruta al archivo PE
        label: Etiqueta descriptiva (ej. "Malware", "Legítimo")
        
    Returns:
        tuple: (vector de features, estadísticas dict)
    """
    print(f"\n{'='*70}")
    print(f"Analizando: {label}")
    print(f"Archivo: {file_path}")
    print(f"{'='*70}")
    
    if not os.path.exists(file_path):
        print(f"❌ ERROR: Archivo no encontrado")
        return None, None
    
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"❌ ERROR: No se pudo parsear PE: {e}")
        return None, None
    
    # Extraer features
    block = ImportsFeatureBlock()
    vec = block.extract(pe, None)
    
    # Calcular estadísticas
    stats = {
        'non_zero_bins': np.count_nonzero(vec),
        'sparsity': 1 - np.count_nonzero(vec) / 1280,
        'max_freq': vec.max(),
        'mean_freq': vec.mean(),
        'std_freq': vec.std(),
        'total_sum': vec.sum(),
    }
    
    # Información del PE original
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        stats['total_dlls'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        stats['total_functions'] = sum(len(dll.imports) for dll in pe.DIRECTORY_ENTRY_IMPORT)
    else:
        stats['total_dlls'] = 0
        stats['total_functions'] = 0
    
    # Imprimir estadísticas
    print(f"\n📊 Estadísticas del Vector de Features:")
    print(f"  Non-zero bins: {stats['non_zero_bins']} / 1280 ({stats['non_zero_bins']/1280*100:.1f}%)")
    print(f"  Sparsity: {stats['sparsity']:.2%}")
    print(f"  Max frecuencia: {stats['max_freq']:.6f}")
    print(f"  Media: {stats['mean_freq']:.6f}")
    print(f"  Desviación estándar: {stats['std_freq']:.6f}")
    print(f"  Suma (normalizada): {stats['total_sum']:.6f}")
    
    print(f"\n📚 Import Table Original:")
    print(f"  Total DLLs: {stats['total_dlls']}")
    print(f"  Total funciones: {stats['total_functions']}")
    
    # Mostrar DLLs más importadas
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print(f"\n  Top 10 DLLs por número de funciones:")
        dll_counts = []
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = dll.dll.decode('utf-8', errors='replace')
                num_funcs = len(dll.imports)
                dll_counts.append((dll_name, num_funcs))
            except:
                pass
        
        dll_counts.sort(key=lambda x: x[1], reverse=True)
        for i, (dll_name, count) in enumerate(dll_counts[:10], 1):
            print(f"    {i:2d}. {dll_name}: {count} funciones")
    
    return vec, stats


def compare_distributions(vec_benign, vec_malware, label_benign="Legítimo", label_malware="Malware"):
    """
    Compara dos distribuciones de imports.
    
    Args:
        vec_benign: Vector de features del archivo benigno
        vec_malware: Vector de features del archivo malicioso
        label_benign: Etiqueta del benigno
        label_malware: Etiqueta del malware
    """
    print(f"\n{'='*70}")
    print(f"COMPARACIÓN: {label_benign} vs {label_malware}")
    print(f"{'='*70}")
    
    # Distancia coseno
    dot = np.dot(vec_benign, vec_malware)
    norm_benign = np.linalg.norm(vec_benign)
    norm_malware = np.linalg.norm(vec_malware)
    
    if norm_benign > 0 and norm_malware > 0:
        cosine_sim = dot / (norm_benign * norm_malware)
        print(f"\n📐 Similitud Coseno: {cosine_sim:.4f}")
        print(f"   (0 = completamente diferente, 1 = idéntico)")
        
        if cosine_sim < 0.3:
            print(f"   ✅ Distribuciones MUY diferentes (excelente separabilidad)")
        elif cosine_sim < 0.6:
            print(f"   ✅ Distribuciones moderadamente diferentes")
        else:
            print(f"   ⚠️  Distribuciones similares (puede dificultar clasificación)")
    
    # Distancia euclidiana
    euclidean_dist = np.linalg.norm(vec_benign - vec_malware)
    print(f"\n📏 Distancia Euclidiana: {euclidean_dist:.4f}")
    
    # Diferencia L1 (Manhattan)
    l1_dist = np.sum(np.abs(vec_benign - vec_malware))
    print(f"📏 Distancia L1 (Manhattan): {l1_dist:.4f}")
    
    # Bins únicos (solo en uno de los dos)
    unique_benign = np.sum((vec_benign > 0) & (vec_malware == 0))
    unique_malware = np.sum((vec_malware > 0) & (vec_benign == 0))
    shared = np.sum((vec_benign > 0) & (vec_malware > 0))
    
    print(f"\n🔍 Bins Activos:")
    print(f"   Solo en {label_benign}: {unique_benign}")
    print(f"   Solo en {label_malware}: {unique_malware}")
    print(f"   Compartidos: {shared}")
    
    # Visualización
    if HAS_MATPLOTLIB:
        visualize_comparison(vec_benign, vec_malware, label_benign, label_malware)


def visualize_comparison(vec_benign, vec_malware, label_benign, label_malware):
    """
    Crea visualizaciones comparativas.
    """
    fig, axes = plt.subplots(3, 1, figsize=(16, 12))
    
    # Plot 1: Distribuciones completas
    x = np.arange(1280)
    axes[0].bar(x, vec_benign, width=1, color='blue', alpha=0.6, label=label_benign)
    axes[0].set_title(f'Distribución de Imports - {label_benign}', fontsize=14, fontweight='bold')
    axes[0].set_xlabel('Hash Bin Index')
    axes[0].set_ylabel('Frecuencia Normalizada')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)
    
    axes[1].bar(x, vec_malware, width=1, color='red', alpha=0.6, label=label_malware)
    axes[1].set_title(f'Distribución de Imports - {label_malware}', fontsize=14, fontweight='bold')
    axes[1].set_xlabel('Hash Bin Index')
    axes[1].set_ylabel('Frecuencia Normalizada')
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)
    
    # Plot 3: Diferencia (overlay)
    axes[2].bar(x, vec_benign, width=1, color='blue', alpha=0.4, label=label_benign)
    axes[2].bar(x, vec_malware, width=1, color='red', alpha=0.4, label=label_malware)
    axes[2].set_title('Comparación Superpuesta', fontsize=14, fontweight='bold')
    axes[2].set_xlabel('Hash Bin Index')
    axes[2].set_ylabel('Frecuencia Normalizada')
    axes[2].legend()
    axes[2].grid(True, alpha=0.3)
    
    plt.tight_layout()
    
    output_path = 'imports_comparison.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"\n📊 Visualización guardada: {output_path}")
    
    # Histograma de frecuencias
    fig2, ax = plt.subplots(1, 1, figsize=(10, 6))
    
    # Solo bins no-cero
    benign_nonzero = vec_benign[vec_benign > 0]
    malware_nonzero = vec_malware[vec_malware > 0]
    
    ax.hist(benign_nonzero, bins=50, alpha=0.6, color='blue', label=label_benign, edgecolor='black')
    ax.hist(malware_nonzero, bins=50, alpha=0.6, color='red', label=label_malware, edgecolor='black')
    ax.set_title('Distribución de Frecuencias (bins no-cero)', fontsize=14, fontweight='bold')
    ax.set_xlabel('Frecuencia')
    ax.set_ylabel('Número de Bins')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    output_path2 = 'imports_histogram.png'
    plt.savefig(output_path2, dpi=150, bbox_inches='tight')
    print(f"📊 Histograma guardado: {output_path2}")


def main():
    """
    Ejecutar análisis comparativo.
    """
    print("="*70)
    print("ANÁLISIS COMPARATIVO: IMPORTS MALWARE VS LEGÍTIMO")
    print("="*70)
    
    # Configurar archivos a comparar
    # Ajustar según disponibilidad
    benign_samples = [
        "samples/procexp.exe",
        "samples/procexp64.exe",
        "samples/notepad.exe",
        "/windows/system32/notepad.exe"
    ]
    
    malware_samples = [
        "samples/malware_sample.exe",
        "samples/suspicious.exe"
    ]
    
    # Encontrar primer sample benigno disponible
    benign_path = None
    for path in benign_samples:
        if os.path.exists(path):
            benign_path = path
            break
    
    # Encontrar primer sample malware disponible
    malware_path = None
    for path in malware_samples:
        if os.path.exists(path):
            malware_path = path
            break
    
    if not benign_path:
        print("\n❌ ERROR: No se encontró ningún archivo legítimo para análisis")
        print("   Sugerencia: colocar un PE benigno en samples/procexp.exe")
        return
    
    if not malware_path:
        print("\n⚠️  WARNING: No se encontró archivo malware para comparación")
        print("   Realizando solo análisis del archivo legítimo")
        
        # Analizar solo benigno
        vec_benign, stats_benign = analyze_file(benign_path, "Software Legítimo")
        return
    
    # Analizar ambos archivos
    vec_benign, stats_benign = analyze_file(benign_path, "Software Legítimo")
    vec_malware, stats_malware = analyze_file(malware_path, "Malware")
    
    if vec_benign is not None and vec_malware is not None:
        compare_distributions(vec_benign, vec_malware, 
                            label_benign="Legítimo", 
                            label_malware="Malware")
    
    print("\n" + "="*70)
    print("✅ ANÁLISIS COMPLETADO")
    print("="*70)


if __name__ == "__main__":
    main()
