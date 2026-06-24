#!/usr/bin/env python3
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from extractors.extractor import PEFeatureExtractor

def test_diagnostics():
    print("======================================================================")
    print("PROBANDO NUEVAS CARACTERÍSTICAS DEL EXTRACTOR ADVERSARIAL")
    print("======================================================================")
    
    extractor = PEFeatureExtractor()
    samples_dir = Path("samples")
    samples_dir.mkdir(exist_ok=True)
    
    # 1. Archivo PE Normal (o simulado de prueba)
    normal_pe = samples_dir / "procexp64.exe"
    if normal_pe.exists():
        print(f"\n[1] Escaneando PE Normal: {normal_pe.name} ({normal_pe.stat().st_size} bytes)")
        vector = extractor.extract(str(normal_pe))
        diag = extractor.last_diagnostics["diagnostics"]
        print(f"    - Modo de Extracción: {diag['extraction_mode']}")
        print(f"    - Razón de Degradación: {diag['degradation_reason']}")
        print(f"    - Bytes Muestreados: {diag['bytes_sampled']}")
        print(f"    - Cobertura Analizada: {diag['percentage_analyzed']}%")
        print(f"    - Tiempo Transcurrido: {diag['extraction_time_ms']} ms")
        print(f"    - Detección de Packer:")
        print(f"        * ¿Packer Detectado?: {diag['packer_indicators']['packer_detected']}")
        print(f"        * Razones: {diag['packer_indicators']['packer_reasons']}")
        print(f"        * ¿UPX?: {diag['packer_indicators']['is_packed_upx']}")
        print(f"        * Secciones RWX: {diag['packer_indicators']['rwx_sections']}")
        print(f"        * Secciones Anómalas: {diag['packer_indicators']['anomalous_sections']}")
        print(f"        * Ratio Virtual/Real: {diag['packer_indicators']['ratio_virtual_real']}")
    else:
        print("\n[1] Omitiendo PE Normal (no se encontró samples/procexp64.exe)")

    # 2. Archivo No-PE (Texto plano, simula evasión o archivo no soportado)
    non_pe = samples_dir / "plain_text.txt"
    non_pe.write_bytes(b"Este es un archivo de texto plano no ejecutable. Sirve para testear el RAW_FALLBACK.")
    print(f"\n[2] Escaneando archivo No-PE (Fallback Crudo): {non_pe.name}")
    vector = extractor.extract(str(non_pe))
    diag = extractor.last_diagnostics["diagnostics"]
    print(f"    - Vector Dims: {len(vector)}")
    print(f"    - Modo de Extracción: {diag['extraction_mode']}")
    print(f"    - Razón de Degradación: {diag['degradation_reason']}")
    print(f"    - Cobertura Analizada: {diag['percentage_analyzed']}%")
    print(f"    - Detección de Packer:")
    print(f"        * ¿Packer Detectado?: {diag['packer_indicators']['packer_detected']}")
    
    # 3. Archivo Gigante / Inflado (Evita OOM con lectura distribuida)
    bloated_file = samples_dir / "bloated_evasion.bin"
    # Escribimos un archivo de 15 MB
    print(f"\n[3] Creando archivo inflado de 15 MB para evadir análisis estático...")
    bloated_file.write_bytes(b"MZ" + b"\x00" * (15 * 1024 * 1024 - 2))
    
    print(f"    Escaneando archivo inflado (Muestreo Distribuido): {bloated_file.name}")
    vector = extractor.extract(str(bloated_file))
    diag = extractor.last_diagnostics["diagnostics"]
    print(f"    - Vector Dims: {len(vector)}")
    print(f"    - Modo de Extracción: {diag['extraction_mode']}")
    print(f"    - Razón de Degradación: {diag['degradation_reason']}")
    print(f"    - Bytes Muestreados: {diag['bytes_sampled']} bytes (Límite 10MB)")
    print(f"    - Cobertura Analizada: {diag['percentage_analyzed']}%")
    
    # 4. Archivo Empacado con UPX simulado
    packed_file = samples_dir / "packed_upx_simulated.bin"
    # Escribimos un archivo con la marca UPX! y entropía alta
    import math
    import random
    high_entropy_bytes = bytes([random.randint(0, 255) for _ in range(1000)])
    packed_file.write_bytes(b"MZ" + b"\x00" * 200 + b"UPX!" + high_entropy_bytes)
    
    print(f"\n[4] Escaneando archivo empacado simulado: {packed_file.name}")
    vector = extractor.extract(str(packed_file))
    diag = extractor.last_diagnostics["diagnostics"]
    print(f"    - Modo de Extracción: {diag['extraction_mode']}")
    print(f"    - Detección de Packer:")
    print(f"        * ¿Packer Detectado?: {diag['packer_indicators']['packer_detected']}")
    print(f"        * ¿UPX Detectado?: {diag['packer_indicators']['is_packed_upx']}")
    print(f"        * Razones: {diag['packer_indicators']['packer_reasons']}")
    
    # Limpieza
    non_pe.unlink(missing_ok=True)
    bloated_file.unlink(missing_ok=True)
    packed_file.unlink(missing_ok=True)
    
    print("\n✅ PRUEBA COMPLETADA EXITOSAMENTE.")

if __name__ == "__main__":
    test_diagnostics()
