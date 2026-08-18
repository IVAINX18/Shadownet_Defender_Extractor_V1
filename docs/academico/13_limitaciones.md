# Limitaciones, Riesgos y Casos de Evasión

> Derivado de auditoría de código, ejecuciones reales y tests. 2026-08-18.
> Se documenta únicamente lo que puede sustentarse en código y ejecuciones verificadas.

---

## Limitaciones actuales

### L-01 — Sin conjunto de evaluación real para el modelo ML

El único conjunto de datos de evaluación disponible (`data/test_set/`) es sintético y no compatible con el scaler de producción. No es posible calcular métricas estadísticas reales del modelo (accuracy, FPR, FNR) sobre datos de campo.

**Impacto**: El sistema no puede reportar rendimiento verificable del modelo ML.

---

### L-02 — BehavioralShield sin integrar

El módulo `core/dynamic/process_monitor.py` existe pero no está conectado al pipeline `scan_file()`. El sistema es completamente estático.

**Impacto**: Malware que sea benigno en análisis estático pero malicioso en ejecución no es detectado.

---

### L-03 — IL Behavioral solo para binarios .NET

El análisis IL requiere tablas de metadatos CLR. Para binarios nativos (C, C++, Delphi, Go, Rust), esta capa no aporta información.

**Impacto**: La cobertura forense de la capa IL se limita al subconjunto de malware .NET.

---

### L-04 — Sin interpretabilidad del modelo ML (no hay SHAP/LIME)

El modelo neuronal es una caja negra. No está implementada ninguna técnica de interpretabilidad de features individuales (SHAP, LIME, Integrated Gradients).

**Impacto**: No es posible determinar qué features del vector de 2381 dimensiones contribuyeron al score. La explicabilidad está disponible solo a nivel de capas heurísticas y IL.

---

### L-05 — Scaler de producción incompatible con el test set

El `scaler.pkl` fue ajustado sobre datos con distribuciones incompatibles con el test set disponible. El pipeline de producción usa el scaler, pero su validación formal es imposible sin el conjunto de entrenamiento original.

**Impacto**: Potencial degradación de rendimiento del modelo si el scaler no está correctamente ajustado para el dominio de datos reales.

---

### L-06 — Reglas YARA generan falsos positivos sobre software legítimo

Confirmado: `procexp64.exe` activa `Keylogger_Generic`. No hay mecanismo de whitelisting implementado.

**Impacto**: En entornos con herramientas de administración, debuggers o profilers, la tasa de FPR puede ser significativa.

---

### L-07 — n8n no alerta para operational_status DANGEROUS con label BENIGN

El caso más valioso de detección (overlay payload, H-01) no genera alerta automatizada.

**Impacto**: La detección heurística más crítica no activa el flujo de respuesta automatizada.

---

### L-08 — JWT expirado produce HTTP 500

Fail-open en autenticación cuando Supabase no está configurado.

**Impacto**: Falla de seguridad menor. El endpoint retorna 500 con log que revela estado de configuración.

---

### L-09 — Muestreo distribuido en archivos >10 MB

Solo el 50.15% de archivos grandes es analizado por el extractor.

**Impacto**: Cobertura reducida. Features maliciosas en regiones no muestreadas podrían evadir el modelo ML.

---

### L-10 — Sin timeout configurable para el extractor

El extractor no tiene límite de tiempo documentado en código (solo el LLM tiene timeout de 30s). Archivos diseñados para inflar el tiempo de extracción (muchas secciones, muchas strings) podrían causar lentitud o DoS local.

---

## Riesgos

### R-01 — Evasión por overlay segmentado

Un atacante podría distribuir el payload en múltiples overlays de menor tamaño, o reducir la entropía del overlay mezclando datos cifrados con datos no cifrados, para bajar `overlay_ratio` y `overlay_entropy` por debajo de los umbrales del Risk Engine.

### R-02 — Evasión por instalador falso

Si un binario malicioso incluye las magic bytes de NSIS o InnoSetup al inicio del overlay, el sistema aplicará el "descuento de instalador" (`test_installer_gets_discount` → PASSED) y reducirá el risk_score, potencialmente evitando la clasificación DANGEROUS.

### R-03 — Evasión del modelo ML por adversarial features

Un atacante con acceso a los artefactos del modelo (best_model.onnx, scaler.pkl) podría calcular perturbaciones en el espacio de features para producir un score bajo manteniendo la funcionalidad maliciosa.

### R-04 — Colisiones en feature hashing de imports

Con 1280 buckets para 1000+ APIs posibles, el feature hashing del extractor de imports tiene alta probabilidad de colisión. APIs con hashes similares son indistinguibles para el modelo.

### R-05 — Dependencia de Ollama para explicabilidad narrativa

Si el servidor Ollama no está disponible, la explicación narrativa no se genera. El sistema fallback solo retorna las evidencias forenses crudas.

### R-06 — Sin cifrado de datos en cuarentena

Los archivos en cuarentena son movidos a `~/.shadownet/quarantine/` con permisos 700, pero no están cifrados. Un atacante con acceso al sistema de archivos podría extraerlos.

---

## Casos de evasión posibles

### CE-01 — Overlay de baja entropía con payload cifrado en segmentos

Técnica: intercalar datos cifrados (alta entropía) con datos de relleno legítimos (baja entropía) para que la entropía promedio del overlay quede bajo 7.2.

**Mitigación posible**: análisis de entropía por bloques en lugar de entropía global del overlay.

### CE-02 — PE con secciones extras para reducir overlay_ratio

Técnica: declarar secciones PE adicionales que cubran la mayor parte del archivo, reduciendo el overlay aparente.

**Mitigación posible**: verificar coherencia entre secciones declaradas y contenido real (discrepancias virtual/raw size).

### CE-03 — Binario nativo sin imports (shellcode loader)

Técnica: un loader con cero imports (carga dinámicas mediante GetProcAddress en runtime) produce un vector de features con Imports=0 y Exports=0. El test `test_no_imports_raises_score` → PASSED muestra que el sistema eleva el score, pero puede no ser suficiente.

### CE-04 — Malware .NET con nombres de clase/método sin indicadores sospechosos

Técnica: renombrar todas las APIs maliciosas a nombres genéricos en el IL y resolver mediante Reflection en runtime. El IL Analyzer detecta Reflection (M2), pero si los strings de la API real nunca aparecen en el IL, la evidencia forense es solo "usa Reflection" sin el nombre de la API.

### CE-05 — Fragmentación del pipeline con delay

Técnica: un binario que detecta análisis sandbox (tiempo de ejecución, VM detection) y no ejecuta el payload en análisis estático. Esto no afecta al sistema actual (análisis estático) pero lo haría ineficaz en un contexto de análisis dinámico futuro.

---

## Futuras mejoras (de la auditoría)

1. Integrar BehavioralShield al pipeline (`core/dynamic/process_monitor.py`).
2. Corregir n8n para alertar sobre `operational_status == "DANGEROUS"` independientemente del label ML.
3. Implementar evaluación con conjunto de datos real y compatible con el scaler.
4. Añadir whitelisting de YARA para software conocido-benigno.
5. Implementar análisis de entropía por bloques en Overlay Analysis.
6. Corregir el manejo de JWT expirado para retornar 401 en lugar de 500.
7. Añadir timeout al extractor de features.
8. Cifrar archivos en cuarentena.
