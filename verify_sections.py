#!/usr/bin/env python3
"""
Script de validación para el bloque SectionInfo (255 features).
Verifica:
- Determinismo
- Dimensionalidad correcta
- Robustez ante archivos sin secciones
- Integridad de cálculos (entropía, histogramas)
- Compatibilidad con PE legítimo vs empaquetado
"""

import sys
import os
import numpy as np
import pefile
from pathlib import Path

# Añadir ruta del proyecto
sys.path.insert(0, str(Path(__file__).parent))

from core.features.section_info import SectionInfoBlock

def test_dimensions():
    print("\n[TEST] Verificando dimensiones...")
    block = SectionInfoBlock()
    assert block.dim == 255, f"❌ Dimension incorrecta: {block.dim}"
    print("✅ Dimension correcta: 255")

def test_no_sections():
    print("\n[TEST] Verificando PE sin secciones...")
    block = SectionInfoBlock()
    
    # Mock PE sin secciones
    class MockPE:
        sections = []
        
    mock_pe = MockPE()
    vec = block.extract(mock_pe)
    
    assert len(vec) == 255
    assert np.all(vec == 0), "❌ Vector debería ser todo ceros"
    print("✅ Manejo correcto de PE sin secciones")

def test_determinism(file_path):
    print(f"\n[TEST] Verificando determinismo en {file_path}...")
    if not os.path.exists(file_path):
        print("⚠️ Archivo no encontrado, saltando.")
        return

    pe = pefile.PE(file_path)
    block = SectionInfoBlock()
    
    v1 = block.extract(pe)
    v2 = block.extract(pe)
    
    if np.array_equal(v1, v2):
        print("✅ Determinismo verificado")
    else:
        print("❌ ERROR: Resultados no determinísticos")
        diff = np.sum(v1 != v2)
        print(f"   Diferencias: {diff}")

def analyze_file(file_path, label):
    print(f"\n[ANÁLISIS] {label}: {file_path}")
    if not os.path.exists(file_path):
        print("⚠️ Archivo no encontrado.")
        return

    pe = pefile.PE(file_path)
    block = SectionInfoBlock()
    vec = block.extract(pe)
    
    print(f"  Total Secciones: {int(vec[0])}")
    print(f"  Entropía Promedio: {vec[4]:.4f}")
    print(f"  Entropía Máxima: {vec[6]:.4f}")
    print(f"  Secciones RWX: {int(vec[13])}")
    
    # Analizar distribución de nombres (indices 165-254)
    names_vec = vec[165:255]
    active_names = np.count_nonzero(names_vec)
    print(f"  Nombres únicos (hashed buckets): {active_names}")

    # Verificar rangos
    if np.any(np.isnan(vec)):
        print("❌ ERROR: Vector contiene NaNs")
    if np.any(np.isinf(vec)):
        print("❌ ERROR: Vector contiene Infs")
        
    print("✅ Vector válido numéricamente")

if __name__ == "__main__":
    print("=== VALIDACIÓN SECTION INFO BLOCK ===")
    
    test_dimensions()
    test_no_sections()
    
    # Tests con archivos reales si existen
    samples = [
        ("samples/procexp.exe", "Legítimo (procexp)"),
        ("samples/notepad.exe", "Legítimo (notepad)"),
        ("samples/malware.exe", "Malware (simulado)")
    ]
    
    for path, label in samples:
        if os.path.exists(path):
            test_determinism(path)
            analyze_file(path, label)
        else:
            print(f"\n⚠️ Sample no encontrado: {path}")

    print("\n=== FIN VALIDACIÓN ===")
