# XAI — Explicabilidad del Sistema

> Fuente: `core/dotnet/il_analyzer.py`, `core/llm/`, `core/heuristics/`,
> `core/explain/shap_explainer.py`, `backend/app/api/routes/explain.py`.
> Auditado 2026-08-18. Actualizado F3 2026-08-27.

---

## Motivación

Un sistema de deteccion de malware que produce solo un score numerico no es directamente accionable para un analista de seguridad. ShadowNet Defender implementa tres niveles de explicabilidad:

1. **XAI Forense** (basado en evidencias deterministas): tokens CLR, strings sospechosos, overlay metrics, YARA rules.
2. **XAI Narrativo** (basado en LLM): Ollama convierte las evidencias forenses en una explicacion en lenguaje natural, con validacion de coherencia (F2 T-10).
3. **XAI SHAP** (F3 T-12): KernelExplainer sobre ONNX Runtime expone las top-20 features del vector de 2381 dimensiones que mas contribuyeron al score ML.

---

## Nivel 1: Evidencias Forenses

### Strings (`#Strings` heap)

El IL Analyzer extrae strings de la tabla `#Strings` del ensamblado CLR. Estas son las cadenas que el código IL referencia directamente como nombres de tipos, métodos, campos y módulos.

**Ejemplo de evidencia real** (capturado por `test_injection_detected`):
```json
{
  "source": "#Strings",
  "value": "VirtualAlloc",
  "location": "MemberRef table, row 0",
  "confidence": "high"
}
```

### Heap de Strings de Usuario (`#US`)

La tabla `#US` (User Strings) contiene strings literales que aparecen en el código IL con instrucción `ldstr`. Son los strings que el programa construye en tiempo de ejecución — URLs, paths, comandos.

**Ejemplo de evidencia** (capturado por `test_networking_detected`):
```json
{
  "source": "#US",
  "value": "http://192.168.1.1/payload",
  "location": "#US heap, offset 0x0042",
  "confidence": "high"
}
```

### Metadata CLR

Los indicadores de obfuscación se derivan de la estructura de metadatos del assembly:

- **Nombres de clase/método no imprimibles**: detectados en `TypeRef` o `MemberRef` (indicador de ofuscador de nombres)
- **Ratio de nombres genéricos (a, b, c, ...)**: patrón de Dotfuscator
- **Presencia de atributos de ofuscación**: `[ObfuscationAttribute]`, `[ConfuserEx]`

**Evidencia en sample2.exe** (ejecución real 2026-08-18):
```
obfuscator_detected: True
obfuscator_name:     Unknown Obfuscator
dotnet_risk_score:   28 (MEDIUM)
il_score:            8
```

### P/Invoke (`ModuleRef` / `ImplMap`)

El IL Analyzer parsea la tabla `ModuleRef` para identificar DLLs externas llamadas vía P/Invoke:

```json
{
  "source": "ModuleRef/PInvoke",
  "value": "kernel32.dll::VirtualAllocEx",
  "location": "ImplMap table, row 3",
  "confidence": "high"
}
```

P/Invoke a `kernel32.dll` con funciones de manipulación de memoria o procesos es un indicador de inyección de código.

**Tests que verifican P/Invoke**:
```
test_injection_detected      → PASSED
test_injection_not_in_legit  → PASSED
```

### Locations

Cada evidencia incluye la ubicación exacta en la estructura CLR:
- Tabla de metadatos (MemberRef, TypeRef, AssemblyRef, ModuleRef)
- Número de fila en la tabla
- Offset en heap (#Strings, #US)

Esto permite que un analista pueda verificar la evidencia manualmente con herramientas como `ildasm`, `dnSpy` o `ilspy`.

---

## Confidence Levels

El sistema asigna niveles de confianza a cada evidencia:

| Nivel | Criterio |
|-------|----------|
| `high` | API o string con semántica inequívocamente maliciosa (VirtualAlloc, CreateRemoteThread, etc.) |
| `medium` | API dual-use que puede ser legítima dependiendo del contexto (Assembly.Load, Process.Start) |
| `low` | Indicador contextual que solo es significativo junto con otros |

Los niveles son asignados estáticamente en el código del IL Analyzer por categoría de indicador, no por análisis dinámico del contexto de ejecución.

---

## Nivel 2: XAI Narrativo — Ollama LLM

### Flujo de explicación

```
ScanResult (JSON completo)
        │
        ▼
PromptBuilder.build_llm_prompt()
        │
        ▼
[Guardrails de seguridad incluidos en el prompt]
        │
        ▼
OllamaClient → Ollama Server (localhost:11434)
        │
        ▼
ExplanationService.parse_response()
        │
        ▼
JSON estructurado:
  - analysis: string
  - threat_level: "high" | "medium" | "low" | "none"
  - behavior_summary: string
  - recommended_actions: list[string]
```

### PromptBuilder (`core/llm/prompt_builder.py`)

Construye el prompt incluyendo:
1. Un resumen del `ScanResult` (campos seleccionados, no el JSON completo — evita prompt injection)
2. Guardrails explícitos: el LLM no debe actuar como agente, no debe ejecutar código, no debe revelar información sobre otros archivos
3. Formato JSON esperado en la respuesta
4. Instrucción de que si el archivo parece benigno, debe decirlo

**Test verificado**:
```
test_build_llm_prompt_contains_guardrails_and_summary → PASSED
test_extract_scan_summary_only_allowed_fields          → PASSED
```

### ExplanationService (`core/llm/explanation_service.py`)

- Ejecuta la llamada LLM en un thread con timeout configurable (default: 30s, vía `LLM_TIMEOUT` env)
- Si el LLM devuelve JSON válido: retorna `parsed_response` estructurado
- Si devuelve texto plano: retorna solo `raw_text`
- Si hay timeout o error de conexión: retorna fallback graceful

**Tests verificados**:
```
test_explanation_service_returns_parsed_response_for_json  → PASSED
test_explanation_service_omits_parsed_response_for_plain_text → PASSED
test_explanation_service_parses_markdown_fenced_json        → PASSED
```

---

## Por qué el sistema puede justificar técnicamente una detección

A diferencia de un modelo ML opaco (caja negra) que produce solo un score, ShadowNet Defender puede justificar cualquier detección con al menos uno de los siguientes elementos:

1. **Si YARA activó**: nombre de la regla + categoría (trojan/spyware/worm/ransomware)
2. **Si ML activó**: score numérico + umbral utilizado (0.5 engine / tripartito backend)
3. **Si Overlay activó**: overlay_ratio, overlay_entropy, embedded_pe_count, indicadores específicos
4. **Si DotNet activó**: obfuscator_name, dotnet_risk_score, factores de riesgo
5. **Si IL Behavioral activó**: lista de evidencias forenses con source, value, location, confidence
6. **Si Risk Engine activó**: lista completa de `triggered_indicators` con valores y umbrales

El campo `heuristic_assessment.justification` en el `ScanResult` contiene una cadena de texto generada programáticamente con todos los indicadores activados.

**Ejemplo real** (sample1.exe, 2026-08-18):
```
"Risk CRITICAL (score=105). Triggered 6 indicator(s):
overlay_ratio=98.7% > 80% |
overlay_ratio=98.7% > 93% (crítico) |
overlay_entropy=7.9987 > 7.2 (cifrado/comprimido) |
overlay_entropy=7.9987 > 7.8 (máxima aleatoriedad) |
global_entropy=7.9861 > 7.5 |
packer_indicators=True"
```

Esta justificación es reproducible, determinista y auditable.

---

## Nivel 3: XAI SHAP — KernelExplainer sobre ONNX (F3 T-12)

### Que es SHAP KernelExplainer

SHAP (SHapley Additive exPlanations) es un framework de teoria de juegos cooperativos que atribuye a cada feature su contribucion marginal al score del modelo. `KernelExplainer` es el metodo de SHAP compatible con cualquier funcion de prediccion (incluido ONNX Runtime), sin necesidad de PyTorch.

### Arquitectura

```
GET /explain/shap?file_path=/ruta/al/archivo.exe&top_k=20
        │
        ▼
_validate_file_path()          # Rechaza path traversal y archivos inexistentes
        │
        ▼
PEFeatureExtractor.extract()   # Vector 2381 dims (mismo que en inferencia ONNX)
        │
        ▼
ShapExplainer.explain()        # core/explain/shap_explainer.py
    scaler.transform()         # StandardScaler (mismo que en inferencia)
    KernelExplainer(background=100 muestras, predict_fn=onnx_session)
    shap_values(nsamples=100)  # Timeout de 30s con ThreadPoolExecutor
        │
        ▼
{top_features, base_value, model_score}
```

### Dependencias

- `onnxruntime` (ya en `base.in`)
- `numpy` (ya en `base.in`)
- `joblib` (ya en `base.in`)
- `shap>=0.44.0` (en `ml.in` — NO en `base.in` para no contaminar prod)

**Invariante**: `torch` no debe estar en `requirements/base.in`. El test `test_shap_no_torch_in_base` verifica este invariante en CI.

### Ejemplo de respuesta

```json
{
  "top_features": [
    {"feature_idx": 0,    "feature_name": "byte_histogram_0",  "shap_value":  0.0842},
    {"feature_idx": 1024, "feature_name": "imports_256",        "shap_value": -0.0317},
    {"feature_idx": 512,  "feature_name": "section_0",          "shap_value":  0.0291}
  ],
  "base_value": 0.1234,
  "model_score": 0.9187
}
```

- `shap_value > 0`: la feature empuja el score hacia MALWARE.
- `shap_value < 0`: la feature empuja el score hacia BENIGN.
- `base_value`: expected value del modelo sobre el background (probabilidad base).
- `model_score`: score ONNX del archivo analizado.

### Limitaciones del Nivel 3 SHAP

1. **No-determinismo**: KernelExplainer con `nsamples=100` produce resultados ligeramente distintos entre ejecuciones por el muestreo Monte Carlo. Las contribuciones absolutas son estables; las relativas pueden variar en features con SHAP cercano a 0.

2. **Latencia**: con `nsamples=100`, la inferencia tarda entre 10-25s en CPU para el vector de 2381 dims. El endpoint tiene un timeout de 30s; si se supera, retorna `{"error": "shap_timeout", "top_features": []}`.

3. **Background sintetico**: si `data/test_set/X_test.npy` no esta disponible, se usa un background sintetico (ceros + gaussiano seed=42). Las contribuciones SHAP son validas pero relativas al background sintetico, no a la distribucion real de entrenamiento.

4. **Nombres de features aproximados**: los nombres de features (`byte_histogram_0`, `imports_256`, etc.) son generados por posicion y reflejan los grupos del extractor SOREL-20M, pero no los nombres internos del entrenamiento original.

---

## Por que el sistema puede justificar tecnicamente una deteccion

A diferencia de un modelo ML opaco (caja negra) que produce solo un score, ShadowNet Defender puede justificar cualquier deteccion con al menos uno de los siguientes elementos:

1. **Si YARA activo**: nombre de la regla + categoria (trojan/spyware/worm/ransomware)
2. **Si ML activo**: score numerico + umbral utilizado (0.5 engine / tripartito backend)
3. **Si Overlay activo**: overlay_ratio, overlay_entropy, embedded_pe_count, indicadores especificos
4. **Si DotNet activo**: obfuscator_name, dotnet_risk_score, factores de riesgo
5. **Si IL Behavioral activo**: lista de evidencias forenses con source, value, location, confidence
6. **Si Risk Engine activo**: lista completa de `triggered_indicators` con valores y umbrales
7. **Si SHAP disponible**: top-20 features por contribucion absoluta al score ONNX

El campo `heuristic_assessment.justification` en el `ScanResult` contiene una cadena de texto generada programaticamente con todos los indicadores activados.

**Ejemplo real** (sample1.exe, 2026-08-18):
```
"Risk CRITICAL (score=105). Triggered 6 indicator(s):
overlay_ratio=98.7% > 80% |
overlay_ratio=98.7% > 93% (critico) |
overlay_entropy=7.9987 > 7.2 (cifrado/comprimido) |
overlay_entropy=7.9987 > 7.8 (maxima aleatoriedad) |
global_entropy=7.9861 > 7.5 |
packer_indicators=True"
```

Esta justificacion es reproducible, determinista y auditable.

---

## Limitaciones del XAI implementado

1. **IL Behavioral solo aplica a .NET**: el analisis de tokens CLR no aplica a binarios nativos (C, C++, Delphi). Para binarios nativos, la capa XAI forense se limita a strings extraidos y analisis de imports.

2. **SHAP disponible desde F3**: el Nivel 3 SHAP requiere `shap>=0.44.0` en `requirements/ml.in` y el endpoint `GET /explain/shap`. En instalaciones con solo `base.in` (prod sin ML), el endpoint retorna `error="shap_not_installed"`.

3. **Ollama requiere servidor local**: la explicacion narrativa requiere un servidor Ollama corriendo. Si no esta disponible, la explicacion forense (nivel 1) sigue siendo accesible pero sin traduccion a lenguaje natural.

4. **Confidence levels son estaticos**: los niveles de confianza son asignados por categoria de indicador en el codigo, no calculados dinamicamente segun el contexto del binario analizado.
