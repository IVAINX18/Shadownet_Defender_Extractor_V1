#!/usr/bin/env python3
"""
Generador de Dataset Mock para Evaluación.
Crea un dataset sintético balanceado (Benign/Malware) de vectores de características
para poder correr los scripts de evaluación científica sin el dataset SOREL de 20TB.

Genera:
- X_test.npy: Matriz de (N_SAMPLES, 2381) features simuladas.
- y_test.npy: Vector de etiquetas (0=Benign, 1=Malware).
"""

import numpy as np
import os

def generate_mock_data(n_samples=1000, n_features=2381):
    print(f"Generando dataset sintético con {n_samples} muestras...")
    
    # 1. Crear etiquetas balanceadas (50% benign, 50% malware)
    y = np.zeros(n_samples, dtype=np.int32)
    n_malware = n_samples // 2
    y[:n_malware] = 1 # Primeros N/2 son malware
    
    # 2. Generar Features Sintéticas
    # Benigno: Valores más bajos en entropía, menos imports raros
    # Malware: Valores más altos en entropía, imports sospechosos, strings raras
    
    X = np.zeros((n_samples, n_features), dtype=np.float32)
    
    # Bloque ByteEntropy (256-511): Malware suele ser más ruidoso
    # Benigno: Normal(0.3, 0.1)
    # Malware: Normal(0.7, 0.1)
    X[n_malware:, 256:512] = np.random.normal(0.3, 0.1, (n_samples - n_malware, 256))
    X[:n_malware, 256:512] = np.random.normal(0.7, 0.1, (n_malware, 256))
    
    # Bloque Imports (943-2222): Malware usa API específica
    # Simulamos bins activos aleatorios pero distintos
    # Malware usa bins [1000-1100] más frecuentemente
    X[:n_malware, 1000:1100] = np.random.choice([0.0, 1.0], size=(n_malware, 100), p=[0.8, 0.2])
    
    # Clip para mantener rango [0, 1] o positivo
    X = np.clip(X, 0.0, 1.0)
    
    # Guardar
    os.makedirs("data/test_set", exist_ok=True)
    np.save("data/test_set/X_test.npy", X)
    np.save("data/test_set/y_test.npy", y)
    
    print(f"✅ Dataset generado en data/test_set/ ({n_samples} muestras)")
    return X, y

if __name__ == "__main__":
    generate_mock_data()
