#!/usr/bin/env python3
"""
Script de Validación Integral del Extractor SOREL-20M.
Verifica que el vector final tenga la forma correcta (2381,) y que todos los bloques funcionen.
"""
import sys
import os
import numpy as np
import time
from pathlib import Path

# Añadir ruta del proyecto
sys.path.insert(0, str(Path(__file__).parent))

from core.features.extractor import PEFeatureExtractor

def test_full_extraction(file_path):
    print(f"\n[TEST] Validación Integral con {file_path}")
    
    if not os.path.exists(file_path):
        print("⚠️ Archivo no encontrado.")
        return

    extractor = PEFeatureExtractor()
    
    start_time = time.time()
    features = extractor.extract(file_path)
    elapsed = (time.time() - start_time) * 1000
    
    # 1. Verificar Shape
    if features.shape == (2381,):
        print(f"✅ Shape Correcto: {features.shape}")
    else:
        print(f"❌ ERROR: Shape Incorrecto {features.shape} (Esperado: 2381)")
        
    # 2. Verificar NaN/Inf
    if np.isnan(features).any() or np.isinf(features).any():
        print("❌ ERROR: El vector contiene NaN o Inf")
    else:
        print("✅ Valores válidos (No NaN/Inf)")
        
    # 3. Verificar Bloques Individuales (muestreo)
    # ByteHistogram (0-256)
    bh_sum = np.sum(features[0:256])
    print(f"  ByteHistogram Sum: {bh_sum:.4f} (Expected ~1.0)")
    
    # ByteEntropy (256-512)
    be_sum = np.sum(features[256:512])
    print(f"  ByteEntropy Sum: {be_sum:.4f} (Expected ~1.0)")
    
    # Strings (512-615)
    str_cnt = features[512] # Log num strings
    print(f"  String Log Count: {str_cnt:.4f}")
    
    # General (616-625)
    file_size = features[616]
    print(f"  File Size: {file_size}")
    
    # Header (626-687)
    print(f"  Header check: {np.any(features[626:688])} (Should be True)")
    
    # Section (688-942)
    sec_ent = features[691] # Avg entropy
    print(f"  Section Avg Entropy: {sec_ent:.4f}")
    
    # Imports (943-2222)
    imp_active = np.count_nonzero(features[943:2223])
    print(f"  Active Import Bins: {imp_active}/1280")
    
    # Exports (2223-2350)
    exp_active = np.count_nonzero(features[2223:2351])
    print(f"  Active Export Bins: {exp_active}/128")
    
    print(f"⏱️ Tiempo de extracción: {elapsed:.2f} ms")

if __name__ == "__main__":
    print("=== VALIDACIÓN FULL EXTRACTOR (2381 features) ===")
    
    sample_path = "samples/procexp.exe"
    if os.path.exists(sample_path):
        test_full_extraction(sample_path)
    else:
        print(f"⚠️ Sample {sample_path} no encontrado.")
        
    print("\n=== FIN VALIDACIÓN ===")
