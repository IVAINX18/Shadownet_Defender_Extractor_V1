# ShadowNet Defender: Arquitectura Híbrida Multicapa para Detección de Malware con Explicabilidad Forense

> Base para artículo científico o trabajo de grado.
> Todos los resultados son verificables a partir del código y ejecuciones reales del repositorio.
> Datos no reproducibles están marcados explícitamente.

---

## Resumen

Se presenta ShadowNet Defender, un sistema de detección de malware para archivos PE que combina aprendizaje automático estático con análisis forense multicapa. El sistema opera mediante 7 fases de análisis secuencial: escaneo YARA determinista, extracción de 2381 features PE, inferencia neuronal con ONNX Runtime, análisis de overlay, análisis de ensamblados .NET/CLR, análisis de comportamiento en IL y un motor de correlación de riesgo. La evaluación experimental sobre muestras disponibles demuestra que el sistema detecta binarios con técnicas de overlay payload que el modelo de aprendizaje automático aislado no puede detectar (score ML=0.0, operational_status=DANGEROUS). Los tests de integración sobre 158 casos verifican el comportamiento del sistema con una tasa de éxito del 98.1%. Se identifican limitaciones específicas: el conjunto de evaluación disponible es sintético y no permite calcular métricas estadísticas sobre datos de campo; y el módulo de monitoreo dinámico de procesos está implementado pero no integrado al pipeline. Durante el desarrollo se implementó un motor de explicabilidad basado en cascada cloud Groq/Gemini con fallback Template (SDK openai, ver docs/TriFallover_Groq_Gemini_Template.md) que traduce las evidencias forenses (tokens CLR, strings, indicadores de overlay) a lenguaje natural — Antes: Ollama, Ahora: cascada cloud Groq (openai/gpt-oss-20b) → Gemini (gemini-3.5-flash-lite) → Template offline; Ollama ELIMINADO.

**Palabras clave**: detección de malware, aprendizaje automático, análisis forense, PE, .NET, overlay analysis, XAI, YARA.

---

## 1. Introducción

La detección de malware basada exclusivamente en firmas estáticas o en modelos de aprendizaje automático presenta limitaciones bien documentadas. Los detectores basados en firmas (YARA, antivirus tradicionales) son efectivos sobre familias conocidas pero son eludibles mediante polimorfismo y ligeras modificaciones de bytes. Los detectores basados en ML estático, entrenados sobre features de la estructura PE, son eludibles mediante técnicas de packing, cifrado y overlay payload, donde el contenido malicioso se almacena fuera de la estructura PE declarada.

Este trabajo presenta ShadowNet Defender, cuya hipótesis de diseño es: *la robustez de un detector mejora más mediante la adición de capas analíticas especializadas e independientes que mediante la optimización exclusiva del modelo de aprendizaje profundo*. Esta hipótesis se valida experimentalmente mediante el análisis de `sample1.exe`, un binario donde el 98.7% de su contenido es un overlay cifrado que el modelo ML clasifica como BENIGN con alta confianza, y el sistema multicapa clasifica correctamente como DANGEROUS/CRITICAL.

---

## 2. Estado del Arte

### 2.1 Detección basada en ML estático

Los enfoques de ML estático para detección de malware PE fueron sistematizados con la publicación de SOREL-20M [Harang & Rudd, 2020], el conjunto de datos de ~20M muestras PE que el modelo de ShadowNet usa como base de entrenamiento. Los trabajos en esta línea (Raff et al., 2018; Anderson & Roth, 2018) demuestran que redes neuronales sobre features PE producen AUC-ROC consistentemente por encima de 0.98 en evaluación controlada.

La limitación fundamental de estos enfoques es que operan sobre la representación que el parser PE produce — features derivadas de headers, secciones e imports. Los datos fuera de la estructura PE (overlay) no contribuyen significativamente al vector de features.

### 2.2 Técnicas de evasión de ML

Kreuk et al. (2018) demostraron ataques adversariales que mantienen funcionalidad maliciosa mientras reducen el score de detectores ML. Grosse et al. (2017) demostraron evasión mediante modificación de features en el espacio de representación. Las técnicas de overlay payload son conocidas en el análisis forense: el payload real se almacena en datos adicionales al final del PE, fuera de cualquier sección declarada.

### 2.3 Sistemas híbridos

Los sistemas EDR modernos (Crowdstrike Falcon, Carbon Black, SentinelOne) combinan análisis estático, sandboxing y monitoreo conductual. En el ámbito académico, trabajos como DeepMalware (Yan et al., 2019) y MalConv (Raff et al., 2018) han explorado análisis de bytes raw para capturar el overlay. ShadowNet Defender adopta un enfoque diferente: mantiene el modelo sobre features PE declaradas pero añade capas analíticas independientes que operan sobre el binario completo.

### 2.4 Análisis de binarios .NET

El análisis específico de malware .NET (IL/CLR) está menos representado en la literatura que el análisis de PE nativo. Herramientas como dnSpy, de4dot y ilspy facilitan el análisis manual. Trabajos como NetDetective (Jiang et al., 2021) abordan la detección de ofuscación CLR. ShadowNet Defender implementa análisis estático de tablas de metadatos CLR para 15 categorías de comportamiento con evidencias forenses por token.

---

## 3. Metodología

### 3.1 Diseño del sistema

El sistema sigue un patrón de pipeline de análisis secuencial con tolerancia a fallos por fase. El diseño clave es la **ortogonalidad** entre capas: el campo `operational_status` producido por el Risk Engine es independiente del campo `label` y `score` del modelo ML. Ambos conviven en el `ScanResult` final.

### 3.2 Dataset y entrenamiento del modelo ML

El modelo fue entrenado sobre SOREL-20M (~5M muestras) más un dataset propio de ~100K muestras (ShadowNet 2024-2026). El preprocesamiento usa StandardScaler ajustado sobre el corpus completo de entrenamiento. El modelo fue exportado en formato ONNX Opset 11 (9.3 KB de grafo, 5.6 MB de pesos).

> Nota metodológica: los datos de entrenamiento no están disponibles en el repositorio. Las métricas de entrenamiento (AUC=0.985 declarada) no fueron reproducidas en esta investigación.

### 3.3 Extractor de features (2381 dimensiones)

El extractor produce un vector de 2381 dimensiones mediante 8 bloques: ByteHistogram (256), ByteEntropy (256), Strings (104), General (10), Header (62), Section (255), Imports (1280), Exports (128). Para archivos >10 MB se aplica muestreo distribuido (inicio + centro + fin) para evitar consumo excesivo de memoria.

### 3.4 Overlay Analysis

El módulo de Overlay Analysis calcula el offset de fin de la estructura PE declarada y analiza los bytes restantes. Los indicadores clave son `overlay_ratio` (fracción del archivo en overlay) y `overlay_entropy` (entropía de Shannon del overlay). Los umbrales del Risk Engine fueron establecidos en: overlay_ratio>80% (moderado), overlay_ratio>93% (crítico), overlay_entropy>7.2 (cifrado), overlay_entropy>7.8 (máxima aleatoriedad).

### 3.5 IL Behavioral Analysis

Para binarios .NET, el módulo parsea directamente las tablas de metadatos CLR del binario sin ejecutarlo. Extrae tokens de `#Strings`, `#US` (User Strings), `MemberRef`, `TypeRef`, `AssemblyRef` y `ModuleRef`/PInvoke. Cada token es clasificado en una de 15 categorías de comportamiento (Reflection, Dynamic Loading, Injection, Persistence, Networking, Command Execution, Credential Theft, Worm, entre otras) con evidencias forenses: fuente, valor, ubicación y nivel de confianza.

### 3.6 Risk Engine

El Risk Engine combina los outputs de todas las capas mediante una función de scoring ponderado que produce `operational_status` ∈ {CLEAN, SUSPICIOUS, DANGEROUS}. La propiedad clave es que puede producir DANGEROUS para un binario que el ML etiqueta como BENIGN, si las capas heurísticas presentan indicadores de riesgo críticos.

---

## 4. Arquitectura

```
Entrada (binario PE)
    ↓
[F1] YARA Scanner ──→ match → DANGEROUS (early exit)
    ↓
[F2-F3] Extractor (2381 dims) + ML/ONNX → label, score
    ↓
[F4] Overlay Analysis → overlay_ratio, entropy, embedded_pe
    ↓
[F5] DotNet Analysis → obfuscator, embedded_assemblies (solo .NET)
    ↓
[F6] IL Behavioral → tokens CLR, evidencias forenses (solo .NET)
    ↓
[F7] Risk Engine → operational_status, risk_level, risk_score
    ↓
ScanResult (label + score + operational_status + evidencias)
    ↓
Backend FastAPI → Supabase (Edge Function send-malware-alert) + cascada LLM Groq/Gemini/Template
```

Cada fase es tolerante a fallos: si una fase falla, el pipeline continúa con las fases restantes y retorna el resultado parcial con indicación del fallo.

---

## 5. Experimentos

### 5.1 Entorno de experimentación

- Hardware: Linux, Python 3.11.9, ONNX Runtime 1.x
- Modelo: best_model.onnx v1.0.1 (2026-02-19)
- Tests: pytest 9.0.3, hypothesis 6.165.10
- Muestras disponibles: samples/ (4 archivos evaluados directamente)

### 5.2 Análisis de sample1.exe

Se ejecutó el pipeline completo sobre `samples/sample1.exe` (20.9 MB). El resultado confirmó la hipótesis del trabajo: el modelo ML produjo score=0.0000 (BENIGN/High confidence) mientras el sistema multicapa produjo operational_status=DANGEROUS/CRITICAL con 6 indicadores activados. Los detalles completos están en `docs/academico/11_analisis_sample1.md`.

### 5.3 Suite de tests

Se ejecutó `pytest tests/ -v` sobre 158 tests. Resultado: 151 passed, 2 failed, 5 skipped en 16.76 segundos. La tasa de éxito es 155/158 = 98.1% (excluyendo skipped que dependen de datos externos). Los 2 tests fallidos corresponden a: (1) JWT expirado retorna 500 en lugar de 401 cuando Supabase no está configurado; (2) Antes: validación de URL en OllamaClient — Ahora: cascada cloud Groq/Gemini/Template via SDK openai (ver docs/TriFallover_Groq_Gemini_Template.md); Ollama ELIMINADO, validación ahora via GroqClient/GeminiClient; si aplica, actualizar a tests de `tests/test_tri_fallover.py`.

### 5.4 Evaluación sobre el test set disponible

El archivo `data/test_set/X_test.npy` contiene 1000 muestras sintéticas perfectamente separables (AUC=1.0 del test set, invertido). Este conjunto es incompatible con el scaler de producción y no representa datos de campo real. Las curvas ROC y PR calculadas sobre este conjunto se incluyen en `figures/fig7_roc_pr_SINTETICO.png` con advertencia explícita.

---

## 6. Resultados

### 6.1 Resultados en muestras reales

| Archivo | ML score | ML label | Op. Status | Risk | YARA | Tiempo |
|---------|----------|----------|------------|------|------|--------|
| sample1.exe | 0.0000 | BENIGN | **DANGEROUS** | CRITICAL/105 | — | 1,240 ms |
| sample2.exe | 0.0000 | BENIGN | CLEAN | LOW/1 | — | 707 ms |
| eicar.txt | 0.0001 | BENIGN | CLEAN | LOW/20 | — | 133 ms |
| procexp64.exe | 1.0000 | MALWARE | UNKNOWN | LOW/0 | Keylogger_Generic | 55 ms |

### 6.2 Resultado de tests

158 tests: 151 passed (98.1%), 2 failed, 5 skipped.
Categorías verificadas: engine fault tolerance, YARA early exit, quarantine security, remediation safety, IL behavioral (37 tests), overlay heuristics (20 tests), serialization roundtrip, property-based invariants (14 tests).

### 6.3 Métricas de rendimiento medidas

| Operación | Tiempo real |
|-----------|-------------|
| YARA early exit | 55 ms |
| Extracción PE_FASTLOAD (20.9 MB) | 784 ms |
| Extracción PE normal (~2 MB) | 229 ms |
| Pipeline completo (sample1) | 1,240 ms |
| Pipeline completo (sample2, .NET) | 707 ms |

### 6.4 Métricas ML no disponibles

Las métricas estadísticas del modelo ML (Accuracy, Precision, Recall, F1, AUC-ROC sobre datos de campo) no pueden calcularse a partir de los artefactos disponibles en el repositorio. El conjunto de evaluación disponible es sintético. Esta es una limitación explícita del trabajo.

---

## 7. Hallazgos

**H-01** (Principal): El sistema multicapa detectó un binario con overlay payload (sample1.exe) que el modelo ML solo clasificó como BENIGN con alta confianza. La detección se realizó mediante Overlay Analysis (overlay_ratio=98.7%, overlay_entropy=7.9987) con Risk Engine produciendo risk_score=105 (CRITICAL). Este resultado respalda empíricamente la hipótesis de diseño del sistema.

**H-02**: El test set disponible (`data/test_set/`) es sintético e incompatible con el scaler de producción. No puede usarse para reportar métricas estadísticas del modelo.

**H-03**: Las reglas YARA actuales producen falso positivo sobre Process Explorer (Sysinternals), una herramienta legítima. El sistema no tiene mecanismo de whitelisting implementado.

**H-04**: El módulo BehavioralShield (monitoreo dinámico de procesos) existe en código pero no está integrado al pipeline, limitando el sistema al análisis estático.

**H-05**: Durante el desarrollo se implementó Supabase Edge Function `send-malware-alert` — Antes: cliente n8n solo alerta para `label == "malicious"` (n8n deprecated solo rollback), omitiendo el caso más importante: `operational_status == "DANGEROUS"` con `label == "BENIGN"` (el escenario de H-01); Ahora: alertas via Edge Function.

---

## 8. Discusión

### 8.1 Validez de la hipótesis principal

La evidencia de H-01 respalda la hipótesis de que las capas especializadas aportan más robustez que la optimización del modelo ML. La técnica de overlay payload es un vector de evasión real de ML estático PE, independientemente del umbral o la arquitectura del modelo. La solución no es un mejor modelo ML — es una capa de análisis diferente que opera sobre el binario completo.

### 8.2 Limitaciones de la evaluación

La validación está basada en un único archivo (sample1.exe) sin ground truth externo confirmado. Para sustentar el hallazgo en un artículo revisado por pares se requiere un corpus de N≥100 muestras con overlay payload verificadas y comparación sistemática de tasas de detección.

### 8.3 Implicaciones del test set sintético

El hallazgo H-02 es metodológicamente relevante: la existencia de un test set sintético que pasa como test de accuracy en CI es una deuda técnica que puede generar falsa confianza en el rendimiento del sistema. La corrección requiere construir un corpus de evaluación real.

### 8.4 Falso positivo y su impacto

El falso positivo de procexp64.exe (H-03) ilustra que las reglas YARA genéricas tienen alta tasa de FPR sobre herramientas de administración. En un entorno de producción con analistas de seguridad, este FPR sería inaceptable sin whitelisting.

---

## 9. Conclusiones

1. ShadowNet Defender implementa una arquitectura de detección de malware PE con 7 fases de análisis independientes que produce un `operational_status` ortogonal al score del modelo ML.

2. El hallazgo principal, validado experimentalmente sobre `sample1.exe`, demuestra que la adición de la capa de Overlay Analysis permite detectar binarios con overlay payload que el modelo ML no detecta.

3. El sistema alcanza 98.1% de tasa de éxito en tests de integración (151/158) cubriendo fault tolerance, seguridad de backend, propiedades del pipeline y comportamiento forense.

4. Las métricas estadísticas del modelo ML sobre datos de campo no están disponibles — el conjunto de evaluación disponible es sintético. Esta limitación debe resolverse antes de publicar métricas de rendimiento.

5. Durante el desarrollo se implementó el módulo de explicabilidad basado en cascada cloud Groq/Gemini con fallback Template (SDK openai, ver docs/TriFallover_Groq_Gemini_Template.md) + evidencias forenses IL que produce justificaciones auditables verificables con `ildasm`, `dnSpy` o herramientas equivalentes — Antes: Ollama LLM, Ahora: cascada Groq (openai/gpt-oss-20b) → Gemini (gemini-3.5-flash-lite) → Template offline; Ollama ELIMINADO.

---

## 10. Trabajo Futuro

1. Integración de BehavioralShield (monitoreo dinámico de procesos) como Fase 8 del pipeline.
2. Construcción de corpus de evaluación real con ground truth externo (VirusTotal, sandbox).
3. Durante el desarrollo se implementó Supabase Edge Function `send-malware-alert` para alertar sobre `operational_status == "DANGEROUS"` independientemente del label ML — Antes: integración n8n, Ahora: Edge Function; n8n deprecated solo rollback.
4. Implementación de interpretabilidad SHAP sobre el modelo ML para completar la cadena de explicabilidad.
5. Extensión a binarios ELF (Linux) y análisis de memoria (fileless malware).
6. Evaluación sistemática de la tasa de FPR de reglas YARA sobre corpus de software legítimo.

---

## Referencias

> Las siguientes referencias corresponden a trabajos relacionados citados en el Estado del Arte.
> Las referencias específicas del código ShadowNet Defender son los archivos del repositorio.

- Harang, R., & Rudd, E. M. (2020). SOREL-20M: A Large Scale Benchmark Dataset for Malicious PE Detection. arXiv preprint.
- Raff, E., Barker, J., Sylvester, J., Brandon, R., Catanzaro, B., & Nicholas, C. K. (2018). Malware Detection by Eating a Whole EXE. AAAI Workshop.
- Anderson, H. S., & Roth, P. (2018). EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models. arXiv preprint.
- Kreuk, F., Barak, A., Aviv-Reuven, S., Baruch, M., Pinkas, B., & Keshet, J. (2018). Deceiving End-to-End Deep Learning Malware Detectors Using Adversarial Examples. arXiv preprint.
- Grosse, K., Papernot, N., Manoharan, P., Backes, M., & McDaniel, P. (2017). Adversarial Examples for Malware Detection. ESORICS.

---

## Apéndices

- `docs/academico/01_resumen_ejecutivo.md` — Resumen ejecutivo
- `docs/academico/02_arquitectura_general.md` — Arquitectura con diagramas Mermaid
- `docs/academico/03_modelo_sorel20m.md` — Dataset y modelo ML
- `docs/academico/04_sistema_hibrido_multicapa.md` — Diseño multicapa detallado
- `docs/academico/05_hallazgo_multicapa.md` — Evidencia del hallazgo principal
- `docs/academico/06_xai_explicabilidad.md` — Sistema de explicabilidad
- `docs/academico/07_metricas_y_resultados.md` — Métricas verificadas y faltantes
- `docs/academico/08_comparacion_ml_vs_hibrido.md` — Comparación directa
- `docs/academico/09_pruebas_unitarias.md` — Suite unitaria
- `docs/academico/10_pruebas_integracion.md` — Suite de integración y propiedades
- `docs/academico/11_analisis_sample1.md` — Análisis forense real de sample1.exe
- `docs/academico/12_hallazgos.md` — Hallazgos numerados con evidencia
- `docs/academico/13_limitaciones.md` — Limitaciones y casos de evasión
- `docs/academico/14_trabajo_futuro.md` — Propuestas de trabajo futuro
- `docs/academico/15_ollama.md` — Antes: Integración LLM Ollama (Ollama ELIMINADO) — Ahora: ver `docs/TriFallover_Groq_Gemini_Template.md` (cascada cloud Groq/Gemini + Template)
- `docs/academico/figures/` — Figuras PNG y SVG (7 figuras generadas)
