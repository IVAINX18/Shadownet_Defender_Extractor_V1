#!/usr/bin/env python3
"""
Script de validación para ExportsFeatureBlock.
Verifica dimensionalidad, determinismo y manejo de casos borde.
"""
import sys
import os
import numpy as np
import pefile
from pathlib import Path

# Añadir ruta del proyecto
sys.path.insert(0, str(Path(__file__).parent))

from core.features.exports import ExportsFeatureBlock

def test_dimensions():
    print("\n[TEST] Verificando dimensiones...")
    block = ExportsFeatureBlock()
    assert block.dim == 128, f"❌ Dimension incorrecta: {block.dim}"
    print("✅ Dimension correcta: 128")

def test_determinism(file_path):
    print(f"\n[TEST] Verificando determinismo en {file_path}...")
    if not os.path.exists(file_path):
        print("⚠️ Archivo no encontrado.")
        return

    try:
        pe = pefile.PE(file_path)
        with open(file_path, 'rb') as f:
            raw_data = f.read()
    except Exception as e:
        print(f"⚠️ Error cargando PE: {e}")
        return

    block = ExportsFeatureBlock()
    v1 = block.extract(pe, raw_data)
    v2 = block.extract(pe, raw_data)
    
    if np.array_equal(v1, v2):
        print("✅ Determinismo verificado (v1 == v2)")
    else:
        print("❌ ERROR: No determinístico")
        print(f"Diff: {v1 - v2}")

def analyze_file(file_path):
    print(f"\n[ANÁLISIS] Archivo: {file_path}")
    if not os.path.exists(file_path):
        print("⚠️ Archivo no encontrado.")
        return

    pe = pefile.PE(file_path)
    with open(file_path, 'rb') as f:
        data = f.read()
    
    block = ExportsFeatureBlock()
    vec = block.extract(pe, data)
    
    active_bins = np.count_nonzero(vec)
    total_sum = np.sum(vec)
    
    print(f"  Bins activos: {active_bins}/128")
    print(f"  Suma total (debe ser 1.0 si hay exports): {total_sum:.4f}")
    
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print(f"  Exports reales en PE: {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)}")
    else:
        print("  Exports reales en PE: 0 (Sin directorio de exportaciones)")

if __name__ == "__main__":
    print("=== VALIDACIÓN EXPORTS BLOCK ===")
    test_dimensions()
    
    # Probar con un binario de sistema que tenga exports (ej: una DLL)
    # Si no hay DLL, usar procexp.exe (aunque exe suele tener 0 exports)
    sample_path = "samples/procexp.exe" # Probablemente 0 exports
    
    # Intentar buscar una DLL del sistema si es posible (solo lectura)
    # Por seguridad, usaremos el sample local. Si tiene 0 exports, verificamos que el vector sea 0.
    
    if os.path.exists(sample_path):
        test_determinism(sample_path)
        analyze_file(sample_path)
    else:
        print(f"\n⚠️ Sample {sample_path} no encontrado.")
        
    print("\n=== FIN VALIDACIÓN ===")
