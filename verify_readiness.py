#!/usr/bin/env python3
"""
Script de Verificación de Integración LLM y Automatización.
Ejecuta un flujo completo simulado para validar:
1. Extracción de features (simulada o real)
2. Inferencia del modelo (MockModel)
3. Generación de Prompts para LLM
4. Configuración del servicio de explicación (Ollama)
"""

import sys
import json
import logging
from pathlib import Path

# Configurar path para imports
sys.path.insert(0, str(Path(__file__).parent))

from core.llm.prompt_builder import build_llm_prompt, extract_scan_summary
from core.llm.explanation_service import ExplanationService, ExplanationServiceConfig
from evaluation._mock_model import MockModel
import numpy as np

# Configurar logging basico
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("ReadinessCheck")

def check_readiness():
    logger.info("=== INICIANDO VERIFICACIÓN DE READINESS ===")
    
    # 1. Verificar MockModel (Simulación de Inferencia)
    logger.info("[1/4] Verificando Inferencia (MockModel)...")
    try:
        model = MockModel()
        # Crear vector dummy (2381 dims)
        X_dummy = np.zeros((1, 2381), dtype=np.float32)
        # Llenar entropía con ruido para simular malware (indices 256-512)
        X_dummy[:, 256:512] = np.random.uniform(0.6, 0.9, (1, 256))
        
        y_pred = model.predict(X_dummy)
        y_prob = model.predict_proba(X_dummy)
        
        logger.info(f"    Predicción: {y_pred[0]} (Prob: {y_prob[0][1]:.4f})")
        if y_pred[0] == 1:
            logger.info("    ✅ MockModel detectó 'Malware' simulado correctamente.")
        else:
            logger.warning("    ⚠️ MockModel no detectó malware simulado (revisar umbrales).")
            
    except Exception as e:
        logger.error(f"    ❌ Fallo en Inferencia: {e}")
        return False

    # 2. Simular Resultado de Escaneo Completo
    scan_result = {
        "file": "suspicious_sample.exe",
        "status": "detected",
        "label": "MALWARE",
        "score": float(y_prob[0][1]),
        "confidence": "High",
        "details": {
            "entropy": 7.8,
            "suspicious_imports": ["kernel32:VirtualAlloc", "kernel32:WriteProcessMemory"],
            "suspicious_sections": [".text", ".rsrc"],
            "top_features": [
                {"name": "high_entropy_section", "value": 7.8, "impact": 0.85},
                {"name": "import_virtualalloc", "value": 1.0, "impact": 0.75}
            ]
        }
    }
    
    # 3. Verificar Generación de Prompts (Prompt Engineering)
    logger.info("[2/4] Verificando Generación de Prompts LLM...")
    try:
        summary = extract_scan_summary(scan_result)
        prompt = build_llm_prompt(scan_result)
        
        # Validaciones de Prompt
        if "Tu tarea NO es detectar malware" not in prompt:
            logger.error("    ❌ Validacion fallida: Prompt no contiene guardrails de seguridad.")
            return False
        
        if "SCAN_SUMMARY" not in prompt:
             logger.error("    ❌ Validacion fallida: Prompt no incluye el resumen de datos.")
             return False
             
        # Verificar tamaño del prompt (no debe ser gigante)
        if len(prompt) > 4000:
            logger.warning(f"    ⚠️ El prompt es muy largo ({len(prompt)} chars). Podría exceder ventana de contexto de modelos pequeños.")
        else:
            logger.info(f"    ✅ Prompt generado correctamente ({len(prompt)} chars).")
            
    except Exception as e:
        logger.error(f"    ❌ Fallo en Prompt Builder: {e}")
        return False

    # 4. Verificar Servicio de Explicación (Extensibilidad)
    logger.info("[3/4] Verificando Arquitectura de Servicio LLM...")
    try:
        # Instanciar servicio sin cliente real (mockeado o default)
        service = ExplanationService()
        
        # Verificar si podemos registrar un nuevo proveedor (Extensibilidad para OpenAI/Opal?)
        class DummyClient:
            def generate(self, prompt, model=None):
                return "Explicación simulada exitosa."
                
        service.register_client("dummy_provider", DummyClient())
        
        response = service.explain(scan_result, provider="dummy_provider")
        if response["response_text"] == "Explicación simulada exitosa.":
            logger.info("    ✅ Servicio LLM es extensible (soporta nuevos providers).")
        else:
            logger.error("    ❌ Fallo al registrar nuevo proveedor LLM.")
            return False
            
    except Exception as e:
        logger.error(f"    ❌ Fallo en Service Architecture: {e}")
        return False
        
    logger.info("=== ✅ VERIFICACIÓN EXITOSA: EL REPO ESTÁ LISTO PARA INTEGRACIÓN LLM AVANZADA ===")
    return True

if __name__ == "__main__":
    success = check_readiness()
    sys.exit(0 if success else 1)
