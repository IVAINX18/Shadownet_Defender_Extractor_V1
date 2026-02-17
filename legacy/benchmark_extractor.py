#!/usr/bin/env python3
"""
Benchmark de Rendimiento para el Extractor SOREL-20M.
Mide tiempo de ejecución y consumo de memoria.
"""
import sys
import os
import time
import psutil
import statistics
import numpy as np
from pathlib import Path

# Añadir ruta del proyecto
sys.path.insert(0, str(Path(__file__).parent))

from core.features.extractor import PEFeatureExtractor

def memory_usage_mb():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024

def run_benchmark(file_paths, iterations=5):
    extractor = PEFeatureExtractor()
    timings = []
    
    print(f"Iniciando benchmark con {len(file_paths)} archivos, {iterations} repeticiones cada uno.")
    
    initial_mem = memory_usage_mb()
    print(f"Memoria inicial: {initial_mem:.2f} MB")
    
    for fp in file_paths:
        if not os.path.exists(fp): continue
        
        file_timings = []
        for _ in range(iterations):
            start = time.time()
            _ = extractor.extract(fp)
            end = time.time()
            file_timings.append((end - start) * 1000) # ms
            
        avg_time = statistics.mean(file_timings)
        timings.append(avg_time)
        print(f"  {os.path.basename(fp)}: {avg_time:.2f} ms (avg)")
        
    final_mem = memory_usage_mb()
    print(f"Memoria final: {final_mem:.2f} MB")
    print(f"Incremento RAM: {final_mem - initial_mem:.2f} MB")
    
    if timings:
        print("\n--- Resultados Globales ---")
        print(f"Promedio: {statistics.mean(timings):.2f} ms")
        print(f"Mediana: {statistics.median(timings):.2f} ms")
        print(f"Min: {min(timings):.2f} ms")
        print(f"Max: {max(timings):.2f} ms")

if __name__ == "__main__":
    # Buscar todos los ejecutables en samples/
    samples_dir = "samples"
    files = []
    if os.path.exists(samples_dir):
        files = [os.path.join(samples_dir, f) for f in os.listdir(samples_dir) if f.endswith(".exe") or f.endswith(".dll")]
    
    if not files:
        print("No hay samples para benchmark.")
        # Usar dummy si no hay nada
        # pass
    else:
        run_benchmark(files)
