#!/usr/bin/env python3
"""
Explicabilidad Global del Modelo (XAI).
Utiliza Permutation Importance (importancia por permutación) para determinar
qué bloques de características son más relevantes para la decisión del modelo.
"""

import numpy as np
import os
import joblib
from sklearn.metrics import accuracy_score

from evaluation._mock_model import MockModel

# 📚 MockModel se importa de evaluation/_mock_model.py
# para evitar duplicación con evaluate_model_metrics.py y test_robustness.py

def explain_global_importance():
    print("=== EXPLICABILIDAD GLOBAL (FEATURE IMPORTANCE) ===")
    
    # Cargar datos
    try:
        X_test = np.load("data/test_set/X_test.npy")
        y_test = np.load("data/test_set/y_test.npy")
    except FileNotFoundError:
        print("❌ Dataset no encontrado. Ejecuta generate_mock_dataset.py primero.")
        return
        
    # Cargar modelo
    model_path = "models/lightgbm_model.pkl"
    if os.path.exists(model_path):
        model = joblib.load(model_path)
    else:
        model = MockModel()
        
    # Baseline Accuracy
    baseline_pred = model.predict(X_test)
    baseline_acc = accuracy_score(y_test, baseline_pred)
    print(f"Baseline Accuracy: {baseline_acc:.4f}\n")
    
    # Definir Bloques — imported from the canonical source to avoid offset drift.
    from extractors.extractor import PEFeatureExtractor
    blocks = {
        f"{i+1}. {name}": rng
        for i, (name, rng) in enumerate(PEFeatureExtractor.BLOCK_RANGES.items())
    }
    
    print("Calculando Permutation Importance por Bloque...")
    print("(Permutando valores y midiendo caída en accuracy)")
    
    results = []
    
    for name, (start, end) in blocks.items():
        # Copia para no dañar original
        X_permuted = X_test.copy()
        
        # Permutar solo las columnas de este bloque
        # Esto rompe la relación feature-target para este bloque específico
        # np.random.shuffle permea solo primera dimensión, necesitamos permutar columnas
        # Shuffle each column independently or block-wise? 
        # Block-wise row shuffle:
        chunk = X_permuted[:, start:end]
        np.random.shuffle(chunk) # Shuffles rows in-place
        X_permuted[:, start:end] = chunk
        
        # Predecir
        perm_pred = model.predict(X_permuted)
        perm_acc = accuracy_score(y_test, perm_pred)
        
        drop = baseline_acc - perm_acc
        results.append((name, drop))
        
        print(f"  {name:20s}: Acc={perm_acc:.4f} (Caída: {drop:.4f})")
        
    # Ordenar por importancia
    results.sort(key=lambda x: x[1], reverse=True)
    
    print("\n------------------------------------------------")
    print("RANKING DE IMPORTANCIA DE BLOQUES")
    print("------------------------------------------------")
    for i, (name, drop) in enumerate(results):
        importance_pct = max(0, drop) * 100
        bar = "█" * int(importance_pct * 200) # Escala visual
        print(f"{i+1}. {name:15s} | {importance_pct:.2f}% | {bar}")
        
    print("\nINTERPRETACIÓN:")
    print("Los bloques con mayor caída son los más críticos para el modelo.")
    print("Si 'ByteEntropy' o 'Imports' están arriba, el modelo mira estructura y comportamiento.")

if __name__ == "__main__":
    explain_global_importance()
