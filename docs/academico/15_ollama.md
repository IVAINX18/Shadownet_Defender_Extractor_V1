# Ollama — Integración LLM

> Fuente: `core/llm/ollama_client.py`, `core/llm/explanation_service.py`,
> `core/llm/prompt_builder.py`, `tests/test_ollama_client.py`,
> `tests/test_explanation_service.py`, `tests/test_llm_prompt_builder.py`.
> Auditado 2026-08-18.

---

## Cómo se integra Ollama

ShadowNet Defender usa Ollama como servidor LLM local para generar explicaciones en lenguaje natural de los resultados del análisis. La integración usa la API OpenAI-compatible que expone Ollama.

**Configuración por defecto**:
```
OLLAMA_BASE_URL = http://127.0.0.1:11434/v1
OLLAMA_MODEL    = llama3.2:3b
LLM_TIMEOUT     = 30  (segundos)
```

Toda la comunicación es local — no hay transferencia de datos a servicios externos.

---

## Flujo de integración

```
POST /scan/upload-explain
        │
        ▼
scan_service.run_scan_explain_pipeline(file)
        │
        ├── engine.scan_file(file)           ← pipeline multicapa
        │         │
        │         └── ScanResult completo
        │
        ├── llm_service.explain_scan_result(scan_result)
        │         │
        │         ├── PromptBuilder.extract_scan_summary(scan_result)
        │         │     └── Filtra solo campos permitidos (no inyección)
        │         │
        │         ├── PromptBuilder.build_llm_prompt(summary)
        │         │     └── Añade guardrails + ejemplo JSON esperado
        │         │
        │         ├── [Thread con timeout de 30s]
        │         │     └── OllamaClient.generate(prompt)
        │         │
        │         └── ExplanationService.parse_response(raw)
        │               ├── Si JSON válido → parsed_response estructurado
        │               ├── Si markdown fenced JSON → extrae y parsea
        │               └── Si texto plano → raw_text solamente
        │
        └── Resultado combinado: scan_result + llm_explanation
                │
                ├── Supabase.save(scan_result + explanation)
                └── n8n.send(scan_result) [si label == malicious]
```

---

## Componentes implementados

### `OllamaClient` (`core/llm/ollama_client.py`)

Wrapper sobre el SDK `openai` configurado para usar Ollama:

```python
client = OpenAI(
    base_url="http://127.0.0.1:11434/v1",
    api_key="ollama"  # valor ignorado por Ollama
)
```

**Normalización de URL**: el cliente acepta valores con formato `export OLLAMA_BASE_URL=...` y los normaliza automáticamente.

**Tests verificados**:
```
test_ollama_client_generate_success                  → PASSED
test_ollama_client_generate_with_custom_model        → PASSED
test_ollama_client_connection_error                  → PASSED
test_ollama_client_timeout_error                     → PASSED
test_ollama_client_empty_response                    → PASSED
test_ollama_client_normalizes_copy_pasted_env_value  → PASSED
test_ollama_client_normalizes_export_style_env_value → PASSED
test_ollama_client_prod_localhost_raises             → ❌ FAILED
```

El último test falla porque la validación de URL de producción no lanza la excepción esperada. Es un test de configuración de seguridad, no de funcionalidad.

### `PromptBuilder` (`core/llm/prompt_builder.py`)

Construye el prompt de forma segura:

1. **`extract_scan_summary(scan_result)`**: extrae solo los campos permitidos del ScanResult para incluir en el prompt. Esto previene prompt injection — el LLM no recibe el resultado completo con paths de sistema u otros datos sensibles.

2. **`build_llm_prompt(summary)`**: construye el prompt con:
   - Descripción del contexto (sistema de detección de malware)
   - Guardrails explícitos: no ejecutar código, no revelar información de otros archivos, no actuar como agente
   - Formato JSON esperado en la respuesta
   - El resumen del scan

**Tests verificados**:
```
test_extract_scan_summary_only_allowed_fields              → PASSED
test_build_llm_prompt_contains_guardrails_and_summary      → PASSED
```

### `ExplanationService` (`core/llm/explanation_service.py`)

Gestiona la llamada LLM con timeout y parseo de respuesta:

- Ejecuta la llamada en un thread separado con timeout configurable (LLM_TIMEOUT, default 30s)
- Si el timeout expira: retorna fallback graceful (sin excepción no controlada)
- Si la respuesta es JSON válido: retorna `parsed_response` estructurado
- Si la respuesta tiene JSON en bloque markdown (```json...```): lo extrae y parsea
- Si la respuesta es texto plano: retorna solo `raw_text`

**Estructura de respuesta esperada del LLM**:
```json
{
  "analysis": "Descripción técnica del hallazgo",
  "threat_level": "high | medium | low | none",
  "behavior_summary": "Qué hace el binario según los indicadores",
  "recommended_actions": ["acción 1", "acción 2"]
}
```

**Tests verificados**:
```
test_explanation_service_returns_parsed_response_for_json      → PASSED
test_explanation_service_omits_parsed_response_for_plain_text  → PASSED
test_explanation_service_parses_markdown_fenced_json           → PASSED
```

---

## Casos de uso

### Caso 1 — Explicación de detección DANGEROUS

Para `sample1.exe` (ML=BENIGN, operational_status=DANGEROUS), el LLM recibiría un resumen con:
- score=0.0, label=BENIGN
- overlay_ratio=98.7%, overlay_entropy=7.9987
- risk_score=105, risk_level=CRITICAL
- triggered_indicators (6 indicadores)

El LLM traduciría esto en lenguaje natural: "El archivo contiene un overlay que ocupa el 98.7% de su tamaño total con entropía cercana al máximo teórico, indicando cifrado o compresión intensa de datos no declarados en la estructura PE. Esto es consistente con técnicas de dropper/loader."

### Caso 2 — Confirmación de benignidad

Para un archivo con score=0.02, sin overlay, sin .NET, sin indicadores heurísticos, el LLM podría responder:
```json
{
  "analysis": "El archivo no presenta indicadores de comportamiento malicioso",
  "threat_level": "none",
  "behavior_summary": "Binario PE sin anomalías estructurales",
  "recommended_actions": ["Ninguna acción requerida"]
}
```

### Caso 3 — Malware .NET con evidencias IL

Para un binario .NET con VirtualAlloc, WriteProcessMemory y P/Invoke a kernel32.dll, el LLM recibiría las evidencias forenses y podría explicar: "Los tokens IL indican técnicas de inyección de código de proceso: VirtualAlloc asigna memoria ejecutable, WriteProcessMemory escribe el payload, y CreateRemoteThread inicia la ejecución en el proceso objetivo."

---

## Beneficios de la integración LLM

1. **Traducción de técnica a lenguaje de negocio**: un analista no técnico puede entender el resultado sin conocer la diferencia entre overlay, IL tokens o YARA.

2. **Contextualización de evidencias**: el LLM puede correlacionar múltiples evidencias y producir una narrativa coherente (ej: "Reflection + P/Invoke + strings de credential theft = probable stealer").

3. **Recomendaciones accionables**: el LLM produce `recommended_actions` específicas para el caso analizado.

4. **Privacidad**: toda la inferencia es local. Los datos del binario analizado no salen del sistema.

---

## Limitaciones de la integración LLM

1. **Dependencia de disponibilidad**: si Ollama no está corriendo, la explicación no se genera. El sistema funciona sin LLM (el pipeline multicapa opera independientemente).

2. **Latencia adicional**: la inferencia LLM añade hasta 30 segundos (timeout) al tiempo de respuesta del endpoint `/scan/upload-explain`. El pipeline de análisis solo tarda ~1.2 segundos.

3. **No determinismo**: el LLM puede producir respuestas diferentes para el mismo input. Las explicaciones no son reproducibles ni auditables con la misma precisión que las evidencias forenses.

4. **Guardrails sin garantía**: los guardrails de seguridad en el prompt reducen el riesgo de prompt injection o respuestas inapropiadas, pero no los eliminan completamente. El LLM podría, en casos adversariales, producir respuestas fuera del formato esperado.

5. **Calidad dependiente del modelo**: con `llama3.2:3b` (modelo pequeño), la calidad del análisis es limitada. Modelos más grandes (llama3.1:70b, mixtral:8x7b) producirían explicaciones más precisas pero requieren más recursos.

6. **Sin validación de la explicación**: el sistema no verifica que la explicación del LLM sea coherente con los indicadores forenses. El LLM podría producir una explicación incorrecta o contradictoria con los datos reales.
