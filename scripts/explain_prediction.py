#!/usr/bin/env python3
"""
Herramienta de Explicabilidad para Predicciones SOREL-20M.
Interpreta el vector de características y explica qué factores (bloques) contribuyen.
Nota: Esto es una heurística basada en la magnitud de features y conocimiento de dominio,
ya que no tenemos los valores SHAP del modelo aquí.
"""
import sys
import os
import numpy as np
from pathlib import Path

# Añadir ruta del proyecto
sys.path.insert(0, str(Path(__file__).parent))

from extractors.extractor import PEFeatureExtractor

def explain_features(features):
    print("\n--- EXPLICACIÓN DE CARACTERÍSTICAS ---")
    
    # Bloques — imported from the canonical source to avoid offset drift.
    from extractors.extractor import PEFeatureExtractor
    blocks = PEFeatureExtractor.BLOCK_RANGES
    
    # 1. Actividad por Bloque (Suma de magnitudes / dimensiones)
    print("Actividad Promedio por Bloque:")
    for name, (start, end) in blocks.items():
        chunk = features[start:end]
        avg_act = np.mean(chunk) # Simple mean
        # Para histogramas L1, la suma es 1.0, mean es 1/dim.
        # Mejor usar Suma para ver "peso" si no estuviera normalizado,
        # pero como están normalizados distinto, es difícil comparar bloques.
        # Usaremos Max value para ver picos.
        max_val = np.max(chunk) if len(chunk) > 0 else 0
        print(f"  {name:15s}: Max={max_val:.4f} | NonZeros={np.count_nonzero(chunk)}")
        
    # 2. Análisis Específicos
    
    # Strings IoC
    print("\nIndicadores de Strings (IoCs):")
    ioc_names = ['Paths', 'URLs', 'Registry', 'MZ', 'IPs', 'Emails', 'APIs', 'PowerShell', 'Crypto', 'Fmt']
    ioc_vals = features[517:527]
    for i, val in enumerate(ioc_vals):
        if val > 0:
            print(f"  ⚠️ Detectado {ioc_names[i]}: {int(val)}")
            
    # Entropía
    avg_entropy = features[691] # Section avg entropy (aprox offset inside block)
    # Actually checking String block global stats
    str_entropy = features[515]
    print(f"\nEntropía de Strings: {str_entropy:.4f} (Alto > 6 indica ofuscación en strings)")
    
    # Imports
    imp_chunk = features[943:2223]
    active_imps = np.count_nonzero(imp_chunk)
    print(f"\nImports: {active_imps} funciones importadas mapeadas.")
    if active_imps < 5:
        print("  ⚠️ Muy pocos imports (sospechoso de packing/syscalls directas)")
        
    # Sections
    # Check RWX section flag
    # Offset section flags is tricky inside the 255 block.
    # Global counts 0-9. Flags 10-14 in SectionBlock relative -> 688+10 = 698
    rwx_count = features[698 + 3] # Exec, Write, Read, RWX, Shared. Index 3 is RWX.
    if rwx_count > 0:
        print(f"\n⚠️ ALERTA: {int(rwx_count)} secciones RWX detectadas (Código modificable/inyectable)")
    
    # General Check
    if features.sum() == 0:
        print("\n❌ VECTOR VACÍO (Posible error de lectura)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        target = "samples/procexp.exe"
    else:
        target = sys.argv[1]
        
    if os.path.exists(target):
        print(f"Analizando: {target}...")
        extractor = PEFeatureExtractor()
        feats = extractor.extract(target)
        explain_features(feats)
    else:
        print("Uso: python explain_prediction.py <archivo.exe>")
