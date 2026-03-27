#!/usr/bin/env python3
"""
Evaluación Científica del Modelo de Detección.
Calcula métricas estándar: Accuracy, Precision, Recall, F1, ROC-AUC.
Genera matriz de confusión y reporte detallado.
"""

import numpy as np
import os
import sys
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
import joblib

from tests._mock_model import MockModel

# 📚 MockModel se importa de tests/_mock_model.py
# para evitar duplicación con test_robustness.py y explain_global_model.py

def evaluate_model():
    print("=== EVALUACIÓN EXPERIMENTAL DEL MODELO ===")
    
    # 1. Cargar Datos
    try:
        X_test = np.load("data/test_set/X_test.npy")
        y_test = np.load("data/test_set/y_test.npy")
    except FileNotFoundError:
        print("❌ Dataset no encontrado. Ejecuta generate_mock_dataset.py primero.")
        return

    print(f"Datos Cargados: {X_test.shape} muestras.")
    
    # 2. Cargar Modelo
    # Intentar cargar modelo real, sino usar Mock
    model_path = "models/lightgbm_model.pkl"
    if os.path.exists(model_path):
        print(f"Cargando modelo real: {model_path}")
        model = joblib.load(model_path)
    else:
        print("⚠️ Modelo real no encontrado. Usando MockModel heurístico para demostracion.")
        model = MockModel()
        
    # 3. Inferencia
    print("Ejecutando inferencia...")
    y_pred = model.predict(X_test)
    try:
        y_prob = model.predict_proba(X_test)[:, 1] # Probabilidad de clase 1 (Malware)
    except Exception:
        y_prob = y_pred # Fallback si no soporta proba
        
    # 4. Cálculo de Métricas
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    try:
        auc = roc_auc_score(y_test, y_prob)
    except Exception:
        auc = 0.0
        
    cm = confusion_matrix(y_test, y_pred)
    
    # 5. Reporte
    print("\n------------------------------------------------")
    print("MÉTRICAS PRINCIPALES")
    print("------------------------------------------------")
    print(f"Accuracy:  {acc:.4f}  (Exactitud global)")
    print(f"Precision: {prec:.4f}  (Calidad de alertas positivas)")
    print(f"Recall:    {rec:.4f}  (Capacidad de detección)")
    print(f"F1-Score:  {f1:.4f}  (Balance Precision/Recall)")
    print(f"ROC-AUC:   {auc:.4f}  (Discriminación independiente de umbral)")
    
    print("\n------------------------------------------------")
    print("MATRIZ DE CONFUSIÓN")
    print("------------------------------------------------")
    print(f"TN (Benignos detectados): {cm[0][0]}")
    print(f"FP (Falsas Alarmas):      {cm[0][1]}")
    print(f"FN (Malware No Detectado):{cm[1][0]}")
    print(f"TP (Malware Detectado):   {cm[1][1]}")
    
    print("\n------------------------------------------------")
    print("INTERPRETACIÓN")
    print("------------------------------------------------")
    if rec < 0.9:
        print("⚠️ ALERTA: Recall bajo. El modelo está dejando pasar malware.")
    if prec < 0.9:
        print("⚠️ ALERTA: Precision baja. Muchas falsas alarmas (fatiga de alertas).")
    if auc > 0.95:
        print("✅ Excelente capacidad de discriminación.")
        
if __name__ == "__main__":
    evaluate_model()
