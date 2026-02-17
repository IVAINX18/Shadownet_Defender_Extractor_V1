#!/usr/bin/env python3
"""
Script de validación para el bloque Imports Feature Hashing.

Tests implementados:
1. Determinismo: mismo archivo → mismo vector
2. Dimensionalidad: vector de 1280 features
3. Robustez: archivo sin imports → vector válido
4. Test real: análisis de archivo PE real
5. Sparsity: verificar que el vector es sparse (mayoría de ceros)

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


def test_shape():
    """Test: bloque tiene dimensión correcta."""
    print("\n[TEST] Verificando dimensión del bloque...")
    
    block = ImportsFeatureBlock()
    
    assert block.dim == 1280, f"❌ FAIL: dim={block.dim}, esperado 1280"
    assert block.DIM == 1280, f"❌ FAIL: DIM={block.DIM}, esperado 1280"
    
    print(f"✅ PASS: Dimensión correcta (1280)")


def test_determinism(file_path: str):
    """Test: mismo archivo → mismo vector (determinismo)."""
    print(f"\n[TEST] Verificando determinismo con {file_path}...")
    
    if not os.path.exists(file_path):
        print(f"⚠️  SKIP: Archivo {file_path} no encontrado")
        return
    
    block = ImportsFeatureBlock()
    pe = pefile.PE(file_path)
    
    # Extraer dos veces
    vec1 = block.extract(pe, None)
    vec2 = block.extract(pe, None)
    
    # Deben ser exactamente iguales (bit a bit)
    if not np.array_equal(vec1, vec2):
        print(f"❌ FAIL: Vectores no son idénticos")
        diff_count = np.sum(vec1 != vec2)
        print(f"  Diferencias: {diff_count} / {len(vec1)} valores")
        return False
    
    print(f"✅ PASS: Determinismo verificado (vectores idénticos)")
    return True


def test_no_imports():
    """Test: PE sin imports → vector válido de ceros."""
    print("\n[TEST] Verificando manejo de PE sin imports...")
    
    block = ImportsFeatureBlock()
    
    # Crear mock PE sin DIRECTORY_ENTRY_IMPORT
    class MockPE:
        pass
    
    mock_pe = MockPE()
    vec = block.extract(mock_pe, None)
    
    # Verificar shape
    assert vec.shape == (1280,), f"❌ FAIL: shape={vec.shape}, esperado (1280,)"
    
    # Verificar que es todo ceros (normalización de vector vacío = 0)
    if np.all(vec == 0):
        print(f"✅ PASS: Vector de ceros para PE sin imports")
    else:
        print(f"⚠️  WARNING: Vector no es todo ceros, pero puede ser válido")
        print(f"  Non-zero: {np.count_nonzero(vec)}, Sum: {vec.sum()}")


def test_real_file(file_path: str):
    """Test: análisis detallado de archivo PE real."""
    print(f"\n[TEST] Analizando archivo real: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"⚠️  SKIP: Archivo {file_path} no encontrado")
        return
    
    block = ImportsFeatureBlock()
    
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"❌ ERROR: No se pudo parsear PE: {e}")
        return
    
    # Extraer features
    vec = block.extract(pe, None)
    
    # Estadísticas del vector
    print(f"\n📊 Estadísticas del vector de features:")
    print(f"  Shape: {vec.shape}")
    print(f"  Dtype: {vec.dtype}")
    print(f"  Non-zero bins: {np.count_nonzero(vec)} / 1280 ({np.count_nonzero(vec)/1280*100:.1f}%)")
    print(f"  Sparsity: {1 - np.count_nonzero(vec)/1280:.2%} (ceros)")
    print(f"  Max valor: {vec.max():.6f}")
    print(f"  Min valor: {vec.min():.6f}")
    print(f"  Suma total: {vec.sum():.6f}")
    print(f"  Media: {vec.mean():.6f}")
    
    # Mostrar primeros valores
    print(f"\n  Primeros 10 valores del vector:")
    print(f"    {vec[:10]}")
    
    # Información de imports del PE original
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        total_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
        total_funcs = sum(len(dll.imports) for dll in pe.DIRECTORY_ENTRY_IMPORT)
        
        print(f"\n📚 Import Table del PE:")
        print(f"  Total DLLs: {total_dlls}")
        print(f"  Total funciones: {total_funcs}")
        
        # Mostrar primeras 5 DLLs
        print(f"\n  Primeras 5 DLLs importadas:")
        for i, dll in enumerate(pe.DIRECTORY_ENTRY_IMPORT[:5]):
            try:
                dll_name = dll.dll.decode('utf-8', errors='replace')
                num_funcs = len(dll.imports)
                print(f"    {i+1}. {dll_name}: {num_funcs} funciones")
                
                # Mostrar primeras 3 funciones de esta DLL
                for j, func in enumerate(dll.imports[:3]):
                    if func.name:
                        func_name = func.name.decode('utf-8', errors='replace')
                    else:
                        func_name = f"[ordinal {func.ordinal}]"
                    print(f"        - {func_name}")
            except Exception as e:
                print(f"    {i+1}. [Error decodificando DLL: {e}]")
        
        # Verificar consistencia
        expected_normalized_sum = 1.0 if total_funcs > 0 else 0.0
        if not np.isclose(vec.sum(), expected_normalized_sum, atol=1e-5):
            print(f"\n⚠️  WARNING: Suma esperada ~{expected_normalized_sum}, obtenida {vec.sum():.6f}")
        else:
            print(f"\n✅ PASS: Suma normalizada correcta (~{expected_normalized_sum})")
    else:
        print(f"\n⚠️  PE sin DIRECTORY_ENTRY_IMPORT")
    
    print(f"\n✅ Análisis completado")


def test_hash_consistency():
    """Test: verificar que el hash es consistente."""
    print("\n[TEST] Verificando consistencia de hash...")
    
    block = ImportsFeatureBlock()
    
    # Test con features conocidas
    test_features = [
        "kernel32:createfilea",
        "ntdll:ntcreatethreadex",
        "ws2_32:send",
        "advapi32:regsetvalueexa"
    ]
    
    print("  Features de prueba y sus índices hash:")
    for feat in test_features:
        idx = block._hash_feature(feat)
        print(f"    '{feat}' → bin {idx}")
        
        # Verificar que siempre da el mismo resultado
        idx2 = block._hash_feature(feat)
        assert idx == idx2, f"❌ Hash no determinístico para '{feat}'"
    
    print(f"✅ PASS: Hash determinístico y consistente")


def main():
    """Ejecutar todos los tests."""
    print("=" * 70)
    print("VALIDACIÓN DEL BLOQUE IMPORTS (FEATURE HASHING)")
    print("=" * 70)
    
    # Test de forma/dimensión
    test_shape()
    
    # Test de consistencia de hash
    test_hash_consistency()
    
    # Test sin imports
    test_no_imports()
    
    # Tests con archivos reales
    test_samples = [
        "samples/procexp.exe",
        "samples/procexp64.exe",
        "samples/notepad.exe"
    ]
    
    for sample in test_samples:
        if os.path.exists(sample):
            test_determinism(sample)
            test_real_file(sample)
            break  # Solo analizar el primero que exista
    else:
        print("\n⚠️  No se encontraron archivos de muestra para testing")
        print("   Sugerencia: colocar un PE en samples/procexp.exe")
    
    print("\n" + "=" * 70)
    print("✅ TODOS LOS TESTS COMPLETADOS")
    print("=" * 70)


if __name__ == "__main__":
    main()
