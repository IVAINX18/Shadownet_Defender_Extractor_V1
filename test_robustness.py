#!/usr/bin/env python3
"""
Pruebas de Robustez (Adversarial Testing).
Evalúa cómo se comporta el modelo ante perturbaciones comunes o intentos de evasión.
"""

import numpy as np
import os
import joblib
from sklearn.metrics import accuracy_score

from evaluation._mock_model import MockModel

# 📚 MockModel se importa de evaluation/_mock_model.py
# para evitar duplicación con evaluate_model_metrics.py y explain_global_model.py

def test_robustness():
    print("=== PRUEBAS DE ROBUSTEZ (ADVERSARIAL) ===")
    
    try:
        X_test = np.load("data/test_set/X_test.npy")
        y_test = np.load("data/test_set/y_test.npy")
    except FileNotFoundError:
        print("❌ Dataset no encontrado. Ejecuta generate_mock_dataset.py primero.")
        return
        
    model_path = "models/lightgbm_model.pkl"
    if os.path.exists(model_path):
        model = joblib.load(model_path)
    else:
        model = MockModel()

    # Baseline
    base_pred = model.predict(X_test)
    base_malware_detect = np.sum((y_test == 1) & (base_pred == 1))
    print(f"Baseline Malware Detectados: {base_malware_detect}/{np.sum(y_test==1)}")
    
    # Escenario 1: Overlay injection (Perturbación de Entropía)
    # Los atacantes añaden bytes aleatorios o ceros al final para cambiar la entropía global.
    # Simulamos esto reduciendo la entropía en el bloque ByteEntropy.
    print("\n[Escenario 1] Overlay Attack (Reducción de Entropía)")
    X_adv_1 = X_test.copy()
    # Reducimos valores de entropía en un 20% (simular padding de ceros)
    X_adv_1[:, 256:512] *= 0.8
    
    pred_1 = model.predict(X_adv_1)
    detect_1 = np.sum((y_test == 1) & (pred_1 == 1))
    print(f"  Malware Detectados tras ataque: {detect_1} (Caída: {base_malware_detect - detect_1})")
    
    if detect_1 < base_malware_detect * 0.9:
        print("  ⚠️ VULNERABILIDAD: El modelo es sensible a manipulación de entropía.")
    else:
        print("  ✅ ROBUSTO: El modelo resiste cambios de entropía simples.")
        
    # Escenario 2: Import Stuffing
    # Añadir imports legítimos para confundir el hash distribution.
    print("\n[Escenario 2] Import Stuffing (Inyección de Imports)")
    X_adv_2 = X_test.copy()
    # Añadimos ruido en bins de imports que suelen ser cero
    noise = np.random.uniform(0, 0.1, (X_test.shape[0], 1280))
    # Solo añadimos (stuffing), no quitamos
    X_adv_2[:, 943:2223] += noise
    # Renormalizar (L1 aproximado)
    row_sums = X_adv_2[:, 943:2223].sum(axis=1, keepdims=True)
    X_adv_2[:, 943:2223] /= (row_sums + 1e-6)
    
    pred_2 = model.predict(X_adv_2)
    detect_2 = np.sum((y_test == 1) & (pred_2 == 1))
    print(f"  Malware Detectados tras ataque: {detect_2} (Caída: {base_malware_detect - detect_2})")
    
if __name__ == "__main__":
    test_robustness()
