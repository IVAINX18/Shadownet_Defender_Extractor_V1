#!/usr/bin/env python3
"""
Script de validación para StringExtractor.
Verifica determinismo, detección de patrones (IoC) y correcta dimensionalidad.
"""
import sys
import os
import numpy as np
import pefile
from pathlib import Path

# Añadir ruta del proyecto
sys.path.insert(0, str(Path(__file__).parent))

from core.features.string_extractor import StringExtractorBlock

def test_dimensions():
    print("\n[TEST] Verificando dimensiones...")
    block = StringExtractorBlock()
    assert block.dim == 104, f"❌ Dimension incorrecta: {block.dim}"
    print("✅ Dimension correcta: 104")

def test_ioc_detection():
    print("\n[TEST] Verificando detección de patrones (IoC)...")
    block = StringExtractorBlock()
    
    # Crear un buffer falso con patrones
    fake_data = (
        b"This is a test string. "
        b"http://malware.com/download.exe "       # URL
        b"192.168.1.100 "                         # IP
        b"C:\\Windows\\System32\\cmd.exe "        # Path + Suspicious process
        b"HKEY_LOCAL_MACHINE\\Software "          # Registry
        b"victim@example.com "                    # Email
        b"LoadLibrary "                           # API
        b"bitcoin wallet "                        # Crypto
    )
    
    # Mock PE (no se usa para Regex ASCII extraction en este bloque, solo raw_data)
    class MockPE: pass
    pe = MockPE()
    
    vec = block.extract(pe, fake_data)
    
    # Verificar que detectó algo
    print(f"  Num Strings (Log): {vec[0]:.4f}")
    
    # Check IoC counts (indices 5-14)
    # 5: Path, 6: URL, 7: Reg, 8: MZ, 9: IP, 10: Email, 11: API, 12: PowerShell, 13: Crypto
    print(f"  URL Count: {vec[6]}")
    print(f"  IP Count: {vec[9]}")
    print(f"  Registry Count: {vec[7]}")
    print(f"  Crypto Count: {vec[13]}")
    
    if vec[6] >= 1 and vec[9] >= 1 and vec[13] >= 1:
        print("✅ IoCs detectados correctamente")
    else:
        print("⚠️  Advertencia: Algunos IoCs no fueron detectados en el buffer sintético")

def test_determinism(file_path):
    print(f"\n[TEST] Verificando determinismo en {file_path}...")
    if not os.path.exists(file_path):
        print("⚠️ Archivo no encontrado.")
        return

    with open(file_path, 'rb') as f:
        data = f.read()
    
    try:
        pe = pefile.PE(data=data)
    except:
        return

    block = StringExtractorBlock()
    v1 = block.extract(pe, data)
    v2 = block.extract(pe, data)
    
    if np.array_equal(v1, v2):
        print("✅ Determinismo verificado")
    else:
        print("❌ ERROR: No determinístico")

def analyze_file(file_path):
    print(f"\n[ANÁLISIS] Archivo: {file_path}")
    if not os.path.exists(file_path):
        print("⚠️ Archivo no encontrado.")
        return

    with open(file_path, 'rb') as f:
        data = f.read()
    pe = pefile.PE(data=data)
    
    block = StringExtractorBlock()
    vec = block.extract(pe, data)
    
    print(f"  Log(Num Strings): {vec[0]:.4f}")
    print(f"  Avg Length: {vec[1]:.2f}")
    print(f"  Avg Entropy: {vec[3]:.4f}")
    
    # IoCs
    ioc_labels = ['Path', 'URL', 'Reg', 'MZ', 'IP', 'Email', 'API', 'PowerShell', 'Crypto', 'Fmt']
    print("  Detecciones IoC:")
    for i, label in enumerate(ioc_labels):
        count = vec[5+i]
        if count > 0:
            print(f"    - {label}: {count}")

if __name__ == "__main__":
    print("=== VALIDACIÓN STRING EXTRACTOR ===")
    test_dimensions()
    test_ioc_detection()
    
    sample_path = "samples/procexp.exe"
    if os.path.exists(sample_path):
        test_determinism(sample_path)
        analyze_file(sample_path)
    else:
        print(f"\n⚠️ Sample {sample_path} no encontrado, saltando analisis real.")
        
    print("\n=== FIN VALIDACIÓN ===")
