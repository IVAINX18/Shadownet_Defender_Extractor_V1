# 🎬 Guión de Demostración — ShadowNet Defender

## Reporte de avances para presentación universitaria

> **Nota 2026-09:** Este guion es histórico (demo universitaria con Ollama local). **Stack vigente:** cascada cloud Groq (`openai/gpt-oss-20b`) → Gemini (`gemini-3.5-flash-lite`) → `TemplateExplainer` offline vía SDK `openai` (ver [`docs/TriFallover_Groq_Gemini_Template.md`](../TriFallover_Groq_Gemini_Template.md)). Ollama fue eliminado; n8n deprecated (solo rollback, ahora Supabase Edge Function `send-malware-alert`).
> Enfoque original de la demo: detección ML + explicación LLM con Ollama local.

---

## 📋 Orden de la demostración

| #   | Qué mostrar                                    | Tiempo aprox. | Archivo/Comando                  |
| --- | ---------------------------------------------- | ------------- | -------------------------------- |
| 1   | Verificar Ollama corriendo + modelo descargado | 2 min         | `fix-ollama.sh`                  |
| 2   | Métricas del modelo ML (precisión, recall, F1) | 3 min         | `evaluate_model_metrics.py`      |
| 3   | Pruebas de robustez adversarial                | 3 min         | `test_robustness.py`             |
| 4   | Explicabilidad global (feature importance)     | 2 min         | `explain_global_model.py`        |
| 5   | Escaneo de archivo real (PE) por CLI           | 2 min         | `cli.py scan`                    |
| 6   | Explicación LLM con Ollama local               | 3 min         | `cli.py scan --explain`          |
| 7   | API local + endpoint /llm/explain              | 3 min         | `api_server.py` + `curl`         |
| 8   | Tests unitarios automatizados                  | 2 min         | `pytest`                         |
| 9   | Verificación de readiness completa             | 2 min         | `verify_readiness.py`            |
| 10  | Mención: Render + n8n + Cloudflare Tunnel      | 2 min         | Mostrar `render.yaml` y diagrama |

---

## 🔧 Preparación previa (antes de la demo)

Ejecuta esto **antes** de la presentación para que todo esté listo:

```bash
# 1. Instalar dependencias del proyecto
pip install -r requirements.txt

# 2. Verificar/instalar Ollama + descargar modelo
chmod +x fix-ollama.sh
./fix-ollama.sh

# 3. Verificar que Ollama responde
curl http://localhost:11434/v1/models

# 4. Configurar variables de entorno para uso local
export OLLAMA_BASE_URL="http://localhost:11434/v1"
export OLLAMA_MODEL="llama3.2:3b"
```

---

## 🎯 DEMO 1 — Ollama funcionando (2 min)

**Qué demuestras:** Que el LLM está corriendo localmente.

```bash
# Verificar que Ollama está activo
ollama list

# Ver modelos cargados en memoria
ollama ps

# Test rápido del endpoint
curl http://localhost:11434/v1/models
```

**Qué decir:** _"Ollama es un servidor de modelos de lenguaje que corre localmente. Aquí vemos que tenemos el modelo llama3.2:3b descargado y listo. Este modelo se usa para generar explicaciones técnicas de los resultados de detección."_

---

## 🎯 DEMO 2 — Métricas del modelo ML (3 min)

**Archivo:** [`evaluate_model_metrics.py`](../evaluate_model_metrics.py)

```bash
python evaluate_model_metrics.py
```

**Salida esperada:**

```
=== EVALUACIÓN EXPERIMENTAL DEL MODELO ===
Datos Cargados: (1000, 2381) muestras.
------------------------------------------------
MÉTRICAS PRINCIPALES
------------------------------------------------
Accuracy:  0.9XXX
Precision: 0.9XXX
Recall:    0.9XXX
F1-Score:  0.9XXX
ROC-AUC:   0.9XXX
------------------------------------------------
MATRIZ DE CONFUSIÓN
------------------------------------------------
TN (Benignos detectados): XXX
FP (Falsas Alarmas):      XX
FN (Malware No Detectado): XX
TP (Malware Detectado):   XXX
```

**Qué decir:** _"El modelo fue entrenado con el dataset SOREL-20M de 20 millones de muestras reales. Aquí vemos las métricas de evaluación: Accuracy, Precision, Recall, F1-Score y ROC-AUC. El Recall es especialmente importante porque mide cuánto malware detectamos — un Recall bajo significa que estamos dejando pasar amenazas."_

---

## 🎯 DEMO 3 — Pruebas de robustez adversarial (3 min)

**Archivo:** [`test_robustness.py`](../test_robustness.py)

```bash
python test_robustness.py
```

**Qué decir:** _"Estas pruebas simulan técnicas de evasión que usan los atacantes reales: inyección de bytes para cambiar la entropía, perturbación de imports, y ruido gaussiano. Verificamos que el modelo mantiene su capacidad de detección incluso bajo estas condiciones adversariales."_

---

## 🎯 DEMO 4 — Explicabilidad global del modelo (2 min)

**Archivo:** [`explain_global_model.py`](../explain_global_model.py)

```bash
python explain_global_model.py
```

**Qué decir:** _"Usamos Permutation Importance para entender qué bloques de características son más relevantes para la decisión del modelo. Esto es clave para la explicabilidad (XAI) — no solo detectamos malware, sino que podemos explicar por qué."_

---

## 🎯 DEMO 5 — Escaneo de archivo real por CLI (2 min)

**Archivo:** [`cli.py`](../cli.py)

```bash
# Escaneo simple (solo ML, sin LLM)
python cli.py scan samples/procexp64.exe
```

**Salida esperada:** JSON con `score`, `label`, `confidence`, `details`.

**Qué decir:** _"Aquí escaneamos un ejecutable real (Process Explorer de Microsoft). El motor ML extrae 2,381 características del archivo PE, las normaliza con el scaler, y las pasa por el modelo ONNX para obtener un score de maliciosidad."_

---

## 🎯 DEMO 6 — Explicación LLM con Ollama (3 min) ⭐ DEMO PRINCIPAL

**Archivo:** [`cli.py`](../cli.py) + [`core/llm/ollama_client.py`](../core/llm/ollama_client.py)

```bash
# Escaneo + explicación LLM (requiere Ollama corriendo)
export OLLAMA_BASE_URL="http://localhost:11434/v1"
export OLLAMA_MODEL="llama3.2:3b"

python cli.py scan samples/procexp64.exe --explain --provider ollama --model llama3.2:3b
```

**Alternativa con scan simulado (si el escaneo real tarda):**

```bash
python cli.py llm-explain --scan-json samples/malware_simulated_scan.json --provider ollama --model llama3.2:3b
```

**Salida esperada:** JSON con `scan_result` + bloque `llm` con `response_text` conteniendo la explicación técnica.

**Qué decir:** _"Aquí es donde entra la IA generativa. Después de que el modelo ML clasifica el archivo, enviamos el resultado a Ollama (un LLM corriendo localmente) que genera una explicación técnica estructurada. El LLM NO detecta malware — solo explica el resultado del modelo ML. Esto es clave: separamos la detección (ML) de la explicación (LLM)."_

---

## 🎯 DEMO 7 — API local + endpoint /llm/explain (3 min)

**Archivo:** [`api_server.py`](../api_server.py)

**Terminal 1 — Levantar API:**

```bash
export OLLAMA_BASE_URL="http://localhost:11434/v1"
export OLLAMA_MODEL="llama3.2:3b"
python -m uvicorn api_server:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — Probar endpoints:**

```bash
# Health check
curl http://localhost:8000/health

# Explicación LLM vía API
curl -X POST "http://localhost:8000/llm/explain" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "ollama",
    "model": "llama3.2:3b",
    "scan_result": {
      "label": "MALWARE",
      "score": 0.97,
      "confidence": "High",
      "details": {
        "entropy": 7.89,
        "suspicious_imports": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
        "suspicious_sections": [".rwx", ".packed"],
        "top_features": [
          {"name": "imports_hash_10", "value": 0.91, "impact": "high"},
          {"name": "section_entropy_high", "value": 0.87, "impact": "high"}
        ]
      }
    }
  }'
```

**Qué decir:** _"La API FastAPI expone los mismos endpoints que usará Render en producción. El endpoint /llm/explain recibe un resultado de escaneo y devuelve la explicación del LLM. En producción, esta API corre en Render y se conecta a Ollama vía Cloudflare Tunnel."_

---

## 🎯 DEMO 8 — Tests unitarios (2 min)

**Archivos:** [`tests/test_ollama_client.py`](../tests/test_ollama_client.py), [`tests/test_llm_prompt_builder.py`](../tests/test_llm_prompt_builder.py)

```bash
python -m pytest tests/test_ollama_client.py tests/test_llm_prompt_builder.py -v
```

**Salida esperada:**

```
tests/test_ollama_client.py::test_ollama_client_generate_success PASSED
tests/test_ollama_client.py::test_ollama_client_generate_with_custom_model PASSED
tests/test_ollama_client.py::test_ollama_client_connection_error PASSED
tests/test_ollama_client.py::test_ollama_client_timeout_error PASSED
tests/test_ollama_client.py::test_ollama_client_empty_response PASSED
tests/test_ollama_client.py::test_ollama_client_prod_localhost_raises PASSED
tests/test_llm_prompt_builder.py::test_extract_scan_summary_only_allowed_fields PASSED
tests/test_llm_prompt_builder.py::test_build_llm_prompt_contains_guardrails_and_summary PASSED

8 passed
```

**Qué decir:** _"Tenemos tests unitarios que verifican el cliente Ollama, el constructor de prompts, y el manejo de errores. Estos tests usan mocks — no necesitan Ollama corriendo. Verificamos: respuestas exitosas, modelos custom, errores de conexión, timeouts, respuestas vacías, y validación de entorno de producción."_

---

## 🎯 DEMO 9 — Verificación de readiness (2 min)

**Archivo:** [`verify_readiness.py`](../verify_readiness.py)

```bash
python verify_readiness.py
```

**Qué decir:** _"Este script ejecuta un flujo completo simulado: inferencia del modelo, generación de prompts, y configuración del servicio de explicación. Verifica que todos los componentes están correctamente integrados."_

---

## 🎯 DEMO 10 — Mención de arquitectura cloud (2 min)

**No ejecutar, solo mostrar archivos:**

```bash
# Mostrar configuración de Render
cat render.yaml

# Mostrar diagrama de arquitectura
cat docs/cloudflare-tunnel-setup.md
```

**Qué decir:** _"Para producción, el backend FastAPI se despliega en Render (nube gratuita). Ollama sigue corriendo localmente pero se expone públicamente con Cloudflare Tunnel, que crea una URL HTTPS segura. Render consume esa URL para las explicaciones LLM. Además, tenemos n8n como orquestador de automatización que envía emails y guarda reportes en Google Drive. Esto lo demostraremos en detalle en la próxima presentación."_

Mostrar este diagrama:

```
┌──────────────┐     HTTPS      ┌─────────────────────┐     HTTP       ┌──────────────┐
│ Render (API) │ ──────────────▶│  Cloudflare Tunnel  │──────────────▶│ Ollama :11434│
│ (nube)       │                │  *.trycloudflare.com│               │ (PC local)   │
└──────┬───────┘                └─────────────────────┘               └──────────────┘
       │
       │ webhook
       ▼
┌──────────────┐
│  n8n Cloud   │ → Email + Google Drive + Auditoría
└──────────────┘
```

---

## 📝 Resumen de archivos clave para la demo

| Archivo                               | Propósito                                         |
| ------------------------------------- | ------------------------------------------------- |
| `fix-ollama.sh`                       | Script para instalar/verificar/iniciar Ollama     |
| `evaluate_model_metrics.py`           | Métricas ML: Accuracy, Precision, Recall, F1, AUC |
| `test_robustness.py`                  | Pruebas adversariales de robustez                 |
| `explain_global_model.py`             | Explicabilidad global (feature importance)        |
| `cli.py`                              | CLI unificada (scan, llm-explain, verify-model)   |
| `api_server.py`                       | API FastAPI con endpoints /scan, /llm/explain     |
| `core/llm/ollama_client.py`           | Cliente Ollama (OpenAI SDK)                       |
| `core/llm/prompt_builder.py`          | Constructor de prompts seguros                    |
| `llm_agent_bridge.py`                 | Puente/adaptador LLM                              |
| `verify_readiness.py`                 | Verificación de integración completa              |
| `tests/test_ollama_client.py`         | Tests unitarios del cliente Ollama                |
| `tests/test_llm_prompt_builder.py`    | Tests del constructor de prompts                  |
| `render.yaml`                         | Configuración de deploy en Render                 |
| `samples/malware_simulated_scan.json` | Resultado de escaneo simulado para demos          |

---

## ⚡ Comandos rápidos (cheat sheet)

```bash
# Preparación
pip install -r requirements.txt
./fix-ollama.sh
export OLLAMA_BASE_URL="http://localhost:11434/v1"
export OLLAMA_MODEL="llama3.2:3b"

# Métricas ML
python evaluate_model_metrics.py
python test_robustness.py
python explain_global_model.py

# Escaneo + LLM
python cli.py scan samples/procexp64.exe
python cli.py scan samples/procexp64.exe --explain --provider ollama --model llama3.2:3b
python cli.py llm-explain --scan-json samples/malware_simulated_scan.json --provider ollama

# API
python -m uvicorn api_server:app --host 127.0.0.1 --port 8000
curl http://localhost:8000/health
curl -X POST http://localhost:8000/llm/explain -H "Content-Type: application/json" -d '{"scan_result":{"label":"MALWARE","score":0.97,"confidence":"High","details":{}}}'

# ── DEMO: API en Render (producción) ──
curl https://shadownet-defender-extractor-v2.onrender.com/health

# Tests
python -m pytest tests/test_ollama_client.py tests/test_llm_prompt_builder.py -v

# Readiness
python verify_readiness.py
```
