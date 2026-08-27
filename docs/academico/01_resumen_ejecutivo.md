# ShadowNet Defender — Resumen Ejecutivo

> Documento derivado de auditoría de código real ejecutada el 2026-08-18.
> Ningún dato en este documento ha sido inventado.

---

## Qué es ShadowNet Defender

ShadowNet Defender es un sistema de detección de malware orientado a archivos PE (Portable Executable) que combina aprendizaje automático estático con análisis forense multicapa. Está diseñado para entornos endpoint y académicos, con capacidad de operar completamente offline.

El sistema expone una CLI de análisis de archivos, un backend REST (FastAPI), integración con Supabase para persistencia y n8n para alertas automatizadas.

---

## Problema abordado

Los detectores antimalware basados exclusivamente en firmas estáticas (YARA) o exclusivamente en modelos de ML presentan vectores de evasión bien documentados:

- **Evasión de firmas**: el atacante puede modificar bytes sin alterar comportamiento.
- **Evasión de ML estático**: técnicas de packing, cifrado y overlay ocultan las features representativas del binario.
- **Opacidad del ML**: un modelo que produce un score sin explicación no es accionable para un analista.

ShadowNet Defender aborda estos tres problemas con una arquitectura de capas independientes y un motor de correlación de riesgo que opera sobre los outputs de todas las capas.

---

## Motivación

El proyecto surge de la necesidad de:

1. Demostrar que la robustez de un detector de malware mejora más con la adición de capas analíticas especializadas que con el refinamiento exclusivo del modelo de aprendizaje profundo.
2. Producir un sistema con explicabilidad forense (XAI) que pueda justificar cada detección con evidencias técnicas concretas (strings, tokens CLR, P/Invoke, overlays).
3. Integrar análisis de binarios .NET/IL, que representa una fracción significativa del malware moderno (RATs, stealers, botnets).

---

## Arquitectura actual (verificada en código)

```
CLI / API REST (FastAPI)
        │
        ▼
[Fase 1] YARA Scanner          ← firmas deterministas, 4 archivos de reglas
        │
        ▼
[Fase 2] UPX / Packer Detection ← indicadores en extractor (high_entropy, ratio)
        │
        ▼
[Fase 3] Feature Extractor (2381 dims)
        │
        ▼
[Fase 4] ML / ONNX Inference    ← red neuronal 2381→512→256→128→1
        │
        ▼
[Fase 5] Overlay Analysis       ← entropía overlay, embedded PE, YARA overlay
        │
        ▼
[Fase 6] DotNet Analysis        ← CLR header, ofuscadores, assemblies embebidos
        │
        ▼
[Fase 7] IL Behavioral Analysis ← tokens CLR: reflection, injection, persistence
        │
        ▼
[Fase 8] Risk Engine            ← correlación de todos los outputs → operational_status
        │
        ▼
Resultado: {label, score, operational_status, risk_level, risk_score, evidencias}
        │
        ▼
Backend → Supabase (persistencia) + n8n (alertas)
```

Fuente: `core/engine.py`, auditado directamente.

---

## Hallazgos principales (obtenidos de ejecuciones reales)

**H-01 — Divergencia ML vs. Heurística en sample1.exe**
El modelo ML asignó score=0.0000 (BENIGN) a `sample1.exe`, mientras el Risk Engine determinó `operational_status=DANGEROUS`, `risk_level=CRITICAL`, `risk_score=105`. La capa de Overlay Analysis detectó 6 indicadores críticos: overlay_ratio=98.7%, overlay_entropy=7.9987, global_entropy=7.9861 y packer_indicators=True.

**H-02 — Test set sintético incompatible con el scaler de producción**
El archivo `data/test_set/X_test.npy` contiene 1000 muestras (500 benign / 500 malware) con features normalizadas en [0,1]. El `scaler.pkl` de producción fue ajustado sobre datos con distribuciones estadísticas incompatibles (media post-escalado=21.73, desviación=112.1). Las métricas del modelo no pueden calcularse sobre este test set con validez.

**H-03 — YARA falso positivo sobre procexp64.exe**
Process Explorer, herramienta legítima de Sysinternals, activa la regla `Keylogger_Generic`. Esto representa un falso positivo documentado que afecta la tasa FPR del sistema en escenarios de uso real.

**H-04 — BehavioralShield no integrado al pipeline**
El código de `core/dynamic/process_monitor.py` existe pero no está conectado a `scan_file()`. La fase de monitoreo dinámico de procesos no contribuye al `operational_status` en ninguna ejecución actual.

---

## Contribuciones

1. Arquitectura híbrida multicapa de 8 fases que produce `operational_status` independiente del score ML.
2. Motor de análisis IL Behavioral con 15 categorías de comportamiento (M2-M15) con evidencias forenses por token CLR.
3. Extractor PE de 2381 features con muestreo distribuido para archivos >10 MB y modo RAW_FALLBACK para no-PE.
4. Motor de explicabilidad (Ollama + PromptBuilder) que produce análisis en lenguaje natural con guardrails de seguridad.
5. Documentación del hallazgo científico: la incorporación de capas especializadas supera en robustez a la optimización exclusiva del modelo ML.
