# DOCUMENTACIÓN TÉCNICA INTEGRAL

## ShadowNet Defender (SND) — Extractor V2

**Proyecto:** Shadownet_Defender_Extractor_V2  
**Versión documentada:** 2.0.0  
**Institución:** INNOVASIC Research Lab — Universidad Cooperativa de Colombia  
**Autores:** Ivan Velasco (IVAINX_18) · Santiago Cubillos (VANkLEis)  
**Fecha de elaboración:** Junio 2026  

---

# 1. Resumen Ejecutivo

## 1.1 Qué es el proyecto

**ShadowNet Defender (SND)** es un sistema de ciberseguridad orientado a la **detección estática de malware** en ejecutables Windows (formato PE — *Portable Executable*). Convierte cada binario en un **vector matemático de 2.381 dimensiones**, lo normaliza estadísticamente y lo clasifica mediante una **red neuronal profunda (DNN)** exportada a **ONNX** para inferencia ligera y offline.

El sistema se presenta como:

- **Motor de análisis** (`core/engine.py`): pipeline híbrido YARA → desempacado UPX → ML estático → (opcional) elevación conductual.
- **Extractor de características** (`extractors/`): implementación modular alineada con el estándar EMBER 2.0 / SOREL-20M.
- **Aplicación de escritorio** (Electron + React + FastAPI): interfaz SOC con autenticación Supabase, historial de escaneos y explicaciones LLM locales (Ollama).
- **Capa de automatización** (n8n): alertas y flujos SOC vía webhooks.

## 1.2 Qué problema resuelve

Los motores antivirus tradicionales basados en **firmas estáticas** (hashes MD5/SHA256, reglas YARA puras) son **reactivos**: requieren que el malware ya haya sido analizado por un experto antes de poder detectarlo. Esto los hace vulnerables ante:

- Polimorfismo y metamorfismo.
- Empaquetado y cifrado de binarios.
- Ataques zero-day.
- Técnicas *Living off the Land* (LotL).

ShadowNet resuelve esto aplicando **Machine Learning sobre análisis estático**: el sistema aprende patrones estructurales, estadísticos y semánticos que distinguen malware de software legítimo, **sin ejecutar el archivo** y **sin depender exclusivamente de firmas conocidas**.

## 1.3 Por qué es relevante

| Dimensión | Relevancia |
|-----------|------------|
| **Científica** | Vector de 2.381 dims comparable con literatura state-of-the-art (EMBER, SOREL-20M). |
| **Operativa** | Análisis < 500 ms por archivo; inferencia ONNX < 15 ms; funciona offline. |
| **Académica** | Cierra la brecha entre datasets públicos masivos y herramientas desplegables en producción. |
| **Industrial** | Pipeline híbrido (firmas + ML + LLM explicativo) alineado con arquitecturas SOC modernas. |

## 1.4 Tecnologías utilizadas

| Capa | Tecnología |
|------|------------|
| Lenguaje core | Python 3.11+ |
| Parsing PE | `pefile` |
| ML / inferencia | NumPy, scikit-learn (StandardScaler), ONNX Runtime |
| Entrenamiento (offline) | PyTorch (exportado a ONNX; no requerido en producción) |
| LLM explicativo | Ollama (API OpenAI-compatible) |
| Backend API | FastAPI, Pydantic v2, Uvicorn |
| Frontend | React + Vite + Electron |
| Persistencia | Supabase (Auth + PostgreSQL) |
| Firmas | YARA (`yara-python`) |
| Desempacado | UPX (`upx-ucl` vía subprocess) |
| Automatización | n8n (webhooks) |

## 1.5 Principales aportes

1. **Extractor robusto anti-evasión** con muestreo distribuido, RAW_FALLBACK, límites de recursos y telemetría de diagnóstico.
2. **Pipeline híbrido de 4 fases** que combina detección determinista (YARA), desempacado UPX, ML estático y monitoreo conductual opcional.
3. **Arquitectura modular SOLID/Clean Architecture** extensible por bloques de features (`FeatureBlock` ABC).
4. **Explicabilidad asistida por LLM** con prompts estructurados y salida JSON.
5. **Aplicación desktop offline-first** con sincronización cloud diferida.

---

# 2. Motivación

## 2.1 Problema de la detección tradicional basada en firmas

Los antivirus clásicos operan bajo un ciclo reactivo:

```
Víctima → Análisis humano → Publicación de firma → Detección posterior
```

Durante ese intervalo, el daño ya está hecho. Las firmas identifican **quién es** el malware (identidad/hash), no **cómo se comporta estructuralmente**.

## 2.2 Limitaciones de antivirus convencionales

| Técnica de evasión | Impacto en detección por firmas |
|--------------------|--------------------------------|
| **Polimorfismo** | Hash único en cada iteración; firma invalidada inmediatamente |
| **Metamorfismo** | Reescritura completa del código; imposible detectar por hash |
| **Packing/cifrado** | Firma en disco no corresponde al payload real |
| **Zero-day** | No existe firma previa |
| **LotL** | No hay binario malicioso externo que firmar |

## 2.3 Necesidad de Machine Learning en ciberseguridad

El ML permite **generalización**: detectar variantes nunca vistas si comparten características estadísticas con familias conocidas. El modelo aprende **patrones discriminantes** (entropía, imports, secciones RWX, strings IoC) en lugar de memorizar hashes.

La literatura demuestra que vectores de características estáticas sobre PE alcanzan AUC-ROC > 0.98 con datasets masivos como SOREL-20M (Harang & Rudd, 2020).

## 2.4 Justificación del proyecto

El proyecto nació en la cátedra de Seguridad Informática de la Universidad Cooperativa de Colombia con la pregunta: *¿Es posible automatizar y escalar la experticia humana en detección de malware mediante ML?*

La evolución del proyecto confirma esta hipótesis:

- **V1 (EMBER 2018):** Prueba de concepto funcional, dataset desactualizado.
- **V2 (SOREL-20M, 2026):** Reingeniería completa con extractor robusto, DNN y despliegue ONNX.

---

# 3. Objetivos

## 3.1 Objetivo general

Desarrollar un sistema de detección de malware basado en **aprendizaje profundo sobre análisis estático de PE**, capaz de operar **offline**, explicar sus decisiones mediante **IA generativa local**, e integrarse en flujos SOC automatizados.

## 3.2 Objetivos específicos

| # | Objetivo específico | Estado |
|---|---------------------|--------|
| 1 | Extraer vector de 2.381 características compatible con EMBER 2.0 | ✅ Completado |
| 2 | Entrenar DNN con dataset SOREL-20M (+ colección propia) | ✅ Completado |
| 3 | Exportar modelo a ONNX para inferencia < 2 s | ✅ Completado |
| 4 | Implementar extractor resistente a evasión adversarial | ✅ Completado |
| 5 | Pipeline híbrido YARA + UPX + ML | ✅ Completado |
| 6 | API REST + CLI + aplicación desktop | ✅ Completado |
| 7 | Explicaciones LLM con Ollama | ✅ Completado |
| 8 | Persistencia Supabase + modo offline | ✅ Completado |
| 9 | Integración n8n para alertas | ⚠️ Parcial |
| 10 | Monitoreo conductual en tiempo real | ⚠️ Base implementada |

## 3.3 Alcance real del sistema

**Dentro del alcance:**

- Archivos PE (`.exe`, `.dll`, `.sys`) en disco.
- Análisis estático sin ejecución del binario.
- Clasificación binaria malware/benigno con score continuo [0, 1].
- Detección determinista de familias conocidas vía YARA.
- Desempacado automático UPX previo al análisis ML.

**Fuera del alcance actual:**

- Malware fileless / en memoria (solo módulo base de monitoreo).
- Análisis dinámico en sandbox (Cuckoo, etc.).
- Formatos no-PE (PDF, ELF, scripts) más allá de RAW_FALLBACK parcial.
- Desempacado de packers custom (VMProtect, Themida, etc.).

---

# 4. Arquitectura General

## 4.1 Componentes principales

```
┌─────────────────────────────────────────────────────────────────┐
│                    CAPA DE PRESENTACIÓN                          │
│  frontend/ (React + Electron)  │  tools/cli.py  │  curl/API   │
└────────────────────────┬────────────────────────────────────────┘
                         │ HTTP (localhost:8000)
┌────────────────────────▼────────────────────────────────────────┐
│                    CAPA DE SERVICIOS                             │
│  backend/app/                                                    │
│    ├── api/routes/     (scan, analysis, health)                 │
│    ├── services/       (scan_service, llm_service, offline)     │
│    ├── schemas/dto.py  (ScanResult, enums tripartitos)          │
│    └── integrations/   (supabase_client)                        │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                    CAPA DE DOMINIO (CORE)                        │
│  core/engine.py          — Orquestador híbrido (Facade)         │
│  core/unpacking/         — UPXUnpacker                           │
│  core/llm/               — ExplanationService, OllamaClient     │
│  core/dynamic/           — BehavioralShield (monitoreo)         │
│  core/integrations/      — n8n_client                           │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                    CAPA DE EXTRACCIÓN + ML                       │
│  extractors/             — PEFeatureExtractor + 8 bloques       │
│  models/inference.py     — ShadowNetModel (ONNX + scaler)       │
│  security/yara_scanner.py— YaraScanner                          │
└─────────────────────────────────────────────────────────────────┘
```

## 4.2 Flujo de procesamiento completo

```
Archivo en disco
       │
       ▼
┌──────────────────┐
│  FASE 1: YARA    │── match ──► MALWARE (score=1.0, confianza High)
└────────┬─────────┘
         │ sin match
         ▼
┌──────────────────┐
│  FASE 2: UPX     │── detectado ──► desempacar ──► archivo temporal
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────┐
│  FASE 3: EXTRACCIÓN + ML                         │
│                                                  │
│  1. Muestreo distribuido (si > 10 MB)           │
│  2. Parseo PE (strict → fast_load → RAW_FALLBACK)│
│  3. Extracción por bloques (8 módulos)          │
│  4. Concatenación → vector 2381 dims            │
│  5. StandardScaler (scaler.pkl)                 │
│  6. Inferencia ONNX (best_model.onnx)           │
│  7. Umbral → label MALWARE/BENIGN                │
└────────┬─────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│  FASE 4 (opt.):  │── elevación de riesgo si comportamiento sospechoso
│  BehavioralShield│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Post-proceso:     │
│  - Clasificación   │  benign (<0.4) / suspicious (0.4-0.7) / malicious (>0.7)
│    tripartita      │
│  - LLM explain     │
│  - Supabase save   │
│  - n8n alert       │
└──────────────────┘
```

## 4.3 Dependencias entre módulos

| Módulo | Depende de | Proporciona |
|--------|-----------|-------------|
| `PEFeatureExtractor` | `pefile`, `numpy`, bloques `FeatureBlock` | `np.ndarray(2381,)` |
| `ShadowNetModel` | `onnxruntime`, `joblib`, `scaler.pkl` | `float [0,1]` |
| `ShadowNetEngine` | Extractor + Model + YARA + UPX | `dict` scan_result |
| `scan_service` | `ShadowNetEngine`, DTOs Pydantic | `ScanResult` |
| `ExplanationService` | `OllamaClient`, `prompt_builder` | JSON explicativo |

## 4.4 Diagrama lógico textual (pipeline ML)

```
Archivo PE (.exe/.dll)
        ↓
read_distributed_file()          [si size > 10 MB: inicio+centro+final]
        ↓
_parse_pe()                      [PE_STRICT → PE_FASTLOAD → RAW_FALLBACK]
        ↓
┌───────────────────────────────────────────────────────┐
│ ByteHistogram(256) │ ByteEntropy(256) │ Strings(104) │
│ General(10) │ Header(62) │ Sections(255)             │
│ Imports(1280) │ Exports(128)                          │
└───────────────────────────────────────────────────────┘
        ↓
Vector concatenado (2381 dims, float32)
        ↓
StandardScaler.transform()       [Z-Score: μ, σ precalculados]
        ↓
ONNX InferenceSession.run()      [MLP: 2381→512→256→128→1]
        ↓
Score de maliciosidad [0.0 – 1.0]
        ↓
Umbral (0.5 engine / 0.4-0.7 tripartite backend)
        ↓
Motor de Diagnóstico (last_diagnostics)
        ↓
Resultado Final JSON
```

---

# 5. Dataset — SOREL-20M

## 5.1 Descripción general

| Atributo | Detalle |
|----------|---------|
| **Nombre completo** | Sophos-ReversingLabs 20 Million Dataset |
| **Publicación** | Harang & Rudd (2020), arXiv:2012.07633 |
| **Tamaño** | ~20 millones de muestras |
| **Distribución** | ~10M benignas / ~10M maliciosas |
| **Formato** | Ejecutables PE (Windows) |
| **Etiquetado** | Multi-motor AV + metadatos de familia |
| **Cobertura temporal** | Muestras hasta ~2020 |

## 5.2 Origen y características

SOREL-20M fue creado conjuntamente por **Sophos AI** y **ReversingLabs** como benchmark industrial para detección estática de malware PE. Cada muestra incluye:

- Veredictos de múltiples motores antivirus.
- Etiquetas de familia de malware.
- Metadatos temporales (fecha de primera aparición).
- Nivel de confianza del etiquetado.

## 5.3 Razones para seleccionarlo

1. **Escala:** 20M muestras capturan la varianza real del ecosistema de software mundial.
2. **Modernidad:** Significativamente más reciente que EMBER 2018.
3. **Reproducibilidad científica:** Estándar de facto en papers de detección estática PE.
4. **Diversidad:** Incluye shareware, drivers, juegos, ransomware, adware, spyware, herramientas de pentest.

## 5.4 Dataset híbrido de entrenamiento (implementación SND)

| Fuente | Muestras | Propósito |
|--------|----------|-----------|
| SOREL-20M (subconjunto estratificado) | 5.000.000 | Varianza global industrial |
| ShadowNet-Original (colección propia in-the-wild) | 100.000 | Frescura 2024-2026 |
| **Total** | **5.100.000** | — |

**Técnica de carga:** Memory-mapped files (`numpy.memmap`) para evitar cargar 48 GB en RAM.

## 5.5 Ventajas

- Cobertura representativa de familias de malware modernas.
- Etiquetado multi-motor reduce sesgo de un único AV.
- Compatible con vector EMBER 2.0 de 2.381 dimensiones.
- Benchmark público permite comparación con literatura.

## 5.6 Limitaciones

- Datos hasta 2020; amenazas post-2020 requieren complemento (colección propia).
- Sesgo hacia Windows PE; no cubre Linux/macOS/mobile.
- Etiquetado multi-motor puede incluir falsos positivos/negativos en ground truth.
- No incluye muestras fileless ni scripts puro-texto.

---

# 6. Ingeniería de Características

El vector final $\mathbf{x} \in \mathbb{R}^{2381}$ es la concatenación ordenada de 8 bloques. Los rangos canónicos están definidos en `PEFeatureExtractor.BLOCK_RANGES`:

| Bloque | Rango | Dims | Clase |
|--------|-------|------|-------|
| ByteHistogram | [0, 256) | 256 | Bytes |
| ByteEntropy | [256, 512) | 256 | Entropía |
| Strings | [512, 616) | 104 | Strings/IoC |
| General | [616, 626) | 10 | PE general |
| Header | [626, 688) | 62 | Cabeceras PE |
| Section | [688, 943) | 255 | Secciones |
| Imports | [943, 2223) | 1280 | Imports (hash) |
| Exports | [2223, 2351) | 128 | Exports (hash) |

## 6.1 Features PE — Metadatos generales (10 dims)

**Módulo:** `extractors/general.py`  
**Rango:** índices 616–625

| Índice | Feature | Qué mide | Relevancia |
|--------|---------|----------|------------|
| 0 | Tamaño del archivo | Bytes totales | File bloating, droppers grandes |
| 1 | SizeOfImage | Tamaño en memoria | Discrepancias packer |
| 2 | Presencia debug dir | 0/1 | Binarios de desarrollo vs producción |
| 3 | Número de exports | Conteo | DLLs vs EXEs, malware con exports mínimos |
| 4 | Número total imports | Suma IAT | Packers reducen imports visibles |
| 5–8 | Flags de directorios | BASERELOC, RESOURCE, SECURITY, TLS | Estructura PE anómala |
| 9 | NumberOfSymbols | Símbolos COFF | Binarios sintéticos |

## 6.2 Features PE — Cabeceras (62 dims)

**Módulo:** `extractors/header.py`  
**Rango:** índices 626–687

Extrae campos del COFF Header, Optional Header y Data Directories:

| Campo | Relevancia para detección |
|-------|--------------------------|
| `TimeDateStamp` | Timestomping (fechas imposibles) |
| `Machine` | Arquitectura inusual (x86 vs x64 vs ARM) |
| `Characteristics` | Flags inconsistentes (DLL en EXE) |
| `Subsystem` | GUI sin imports gráficos = sospechoso |
| `DllCharacteristics` | Ausencia ASLR/DEP/CFG en binarios recientes |
| `SizeOfCode`, `AddressOfEntryPoint` | Entry point en sección de datos (packer) |
| Data Directories (Size + VA × 16) | Presencia/ausencia de tablas críticas |

## 6.3 Features de entropía (256 dims)

**Módulo:** `extractors/byte_entropy.py`  
**Rango:** índices 256–511

**Algoritmo:**

1. Ventana deslizante: $w = 2048$ bytes, stride = 1024 (50% overlap).
2. Entropía de Shannon por ventana: $H(W) = -\sum_{k=0}^{255} p_k \log_2(p_k)$, rango [0, 8].
3. Histograma de 256 bins sobre valores de $H$ encontrados.
4. Normalización: suma = 1.0.

**Parámetros anti-evasión:**

- `MAX_ANALYSIS_BYTES = 10 MB`: muestreo distribuido si el archivo excede el límite.
- Protege contra *entropy bombs* y *padding* que inflarían el número de ventanas.

**Relevancia:**

| Valor H | Interpretación |
|---------|---------------|
| ≈ 0 | Padding, datos uniformes |
| ≈ 4–6 | Código compilado normal |
| > 7.2 | Packing, cifrado, compresión — alerta de primer nivel |

## 6.4 Features de strings (104 dims)

**Módulo:** `extractors/string_extractor.py`  
**Rango:** índices 512–615

**Sub-bloques:**

| Sub-bloque | Dims | Contenido |
|------------|------|-----------|
| A: Estadísticas globales | 5 | log1p(num_strings), mean/max length, mean entropy, log1p(total_chars) |
| B: IoCs | 10 | Conteos de URLs, paths, registry, IPs, emails, APIs, PowerShell, crypto, format strings, MZ embebido |
| C: Histograma longitudes | 40 | Distribución log₂(longitud) |
| D: Histograma entropías | 40 | Distribución entropía por string |
| E: Estadísticas de caracteres | 9 | Ratios dígitos/mayúsculas/minúsculas/espacios/especiales |

**Patrones IoC monitorizados:**

- `cmd.exe`, `powershell`, `rundll32`, `VirtualAlloc`, `CreateRemoteThread`
- URLs (`http://`, `https://`)
- Claves de registro (`HKEY_`, `HKLM`, `HKCU`)
- APIs de inyección: `LoadLibrary`, `GetProcAddress`, `WriteProcessMemory`
- Indicadores de ransomware: `bitcoin`, `wallet`, `monero`

**Límites anti-DoS:**

- `MAX_SCAN_BYTES = 10 MB`
- `MAX_STRINGS = 5.000` con muestreo híbrido inteligente

## 6.5 Features de imports (1280 dims)

**Módulo:** `extractors/imports.py`  
**Rango:** índices 943–2222

**Técnica:** Feature Hashing con SHA256 determinístico.

Para cada par `"dll:function"`:

$$\text{idx} = \text{SHA256}(\text{feature}) \mod 1280$$

El vector se normaliza L1 (frecuencias relativas).

**Límites:** máx. 100 DLLs, 500 funciones por DLL.

**Relevancia:** La IAT es la "firma conductual" del binario. Patrones como `CryptEncrypt + FindFirstFile` sugieren ransomware; `GetAsyncKeyState` sugiere keylogger.

## 6.6 Features de exports (128 dims)

**Módulo:** `extractors/exports.py`  
**Rango:** índices 2223–2350

Mismo esquema de hashing SHA256 con dimensión 128. Límite: 500 símbolos exportados.

## 6.7 Features estructurales — Secciones (255 dims)

**Módulo:** `extractors/section_info.py`  
**Rango:** índices 688–942

| Sub-bloque | Dims | Contenido |
|------------|------|-----------|
| Estadísticas globales | 10 | num_sections, secciones raw=0, medias raw/virt, entropía ponderada, min/max, ratio raw/virt, sumas |
| Flags y permisos | 5 | exec, write, read, RWX, shared |
| Histograma entropía | 50 | Distribución H por sección |
| Histograma raw size | 50 | Distribución log₂(raw_size) |
| Histograma virt size | 50 | Distribución log₂(virt_size) |
| Hash nombres | 90 | SHA256 de nombres de sección normalizados |

**Límite anti-DoS:** máx. 96 secciones analizadas.

**Señales críticas:**

- Sección **RWX** (Read+Write+Execute): inyección de código, polimorfismo.
- Ratio VirtualSize/RawSize >> 1: firma clásica de packer.
- Nombres anómalos (`.x867z`, `UPX0`): packers conocidos.

## 6.8 Features de bytes — Histograma (256 dims)

**Módulo:** `extractors/byte_histogram.py`  
**Rango:** índices 0–255

Frecuencia relativa de cada byte [0x00–0xFF]:

$$x_i = \frac{1}{N}\sum_{j=1}^{N} \mathbf{1}(b_j = i)$$

**Interpretación:**

| Patrón | Significado |
|--------|-------------|
| Picos en 0x00, 0x55, 0xC3 | Código x86 compilado |
| Distribución uniforme ≈ 1/256 | Packing/cifrado — "ruido blanco" |
| Concentración ASCII | Scripts/texto embebido |

---

# 7. Modelo de Machine Learning

## 7.1 Arquitectura utilizada

**Tipo:** Perceptrón Multicapa (MLP) — clasificador binario  
**Framework entrenamiento:** PyTorch  
**Framework producción:** ONNX Runtime  

$$\text{Input}(2381) \xrightarrow{\text{BN+ReLU+Drop}(0.3)} \text{Dense}(512) \xrightarrow{\text{BN+ReLU+Drop}(0.2)} \text{Dense}(256) \xrightarrow{\text{BN+ReLU+Drop}(0.1)} \text{Dense}(128) \xrightarrow{\sigma} \text{Output}(1)$$

## 7.2 Cantidad de capas

| Capa | Neuronas | Activación | Regularización |
|------|----------|------------|----------------|
| Entrada | 2381 | — | — |
| Oculta 1 | 512 | ReLU + BatchNorm1d | Dropout 0.3 |
| Oculta 2 | 256 | ReLU + BatchNorm1d | Dropout 0.2 |
| Oculta 3 | 128 | ReLU + BatchNorm1d | Dropout 0.1 |
| Salida | 1 | Sigmoid | — |

**Total capas densas:** 4 (3 ocultas + 1 salida)

## 7.3 Funciones de activación

- **ReLU** en capas ocultas: $\text{ReLU}(x) = \max(0, x)$ — evita gradiente evanescente.
- **Sigmoid** en salida: $P(\text{malware}) \in (0, 1)$ — interpretable como probabilidad.

## 7.4 Entrenamiento

| Parámetro | Valor |
|-----------|-------|
| Loss | Binary Cross-Entropy (BCE) |
| Optimizador | Adam, lr=0.001 |
| Weight Decay | λ = 10⁻⁵ (L2) |
| LR Scheduler | ReduceLROnPlateau (patience=3, factor=0.5) |
| Épocas | 15 |
| Hardware | GPU NVIDIA A100 (CUDA) |
| Data loading | num_workers=4, memmap |
| Early Stopping | Especificado en PRD (monitoreo de validación) |

$$\mathcal{L} = -\frac{1}{N}\sum_{i=1}^{N}\left[y_i \log(\hat{y}_i) + (1-y_i)\log(1-\hat{y}_i)\right]$$

## 7.5 Validación

- Split train/validation sobre subconjunto SOREL-20M.
- Métricas monitorizadas: AUC-ROC, FPR@TPR=90%, TPR@FPR=1%.
- Checkpoint del mejor modelo guardado como `best_model.pth` → exportado a ONNX.

## 7.6 Preprocesamiento — StandardScaler (Z-Score)

$$z_j = \frac{x_j - \mu_j}{\sigma_j + \epsilon}, \quad \epsilon = 10^{-8}$$

Parámetros $\boldsymbol{\mu}, \boldsymbol{\sigma} \in \mathbb{R}^{2381}$ precalculados sobre 5.1M muestras, persistidos en `models/scaler.pkl`.

## 7.7 Hiperparámetros de inferencia

| Parámetro | Valor | Ubicación |
|-----------|-------|-----------|
| Umbral binario (engine) | 0.5 | `configs/settings.py` |
| Alta confianza | > 0.85 o < 0.15 | `HIGH_CONFIDENCE_THRESHOLD` |
| Umbral tripartito benign | < 0.4 | `scan_service.py` |
| Umbral tripartito malicious | > 0.7 | `scan_service.py` |

## 7.8 Razones de diseño

| Decisión | Justificación |
|----------|---------------|
| MLP vs CNN/Transformer | Vector tabular de features hand-crafted; MLP es estándar en literatura EMBER/SOREL |
| BatchNorm | Estabiliza entrenamiento con batches grandes |
| Dropout decreciente | Más regularización en capas cercanas a la entrada |
| Export ONNX | Elimina dependencia PyTorch (~700 MB → ~5 MB runtime) |
| Sigmoid salida | Score interpretable como probabilidad de maliciosidad |

## 7.9 Artefactos del modelo

| Archivo | SHA256 (manifest) | Tamaño |
|---------|-------------------|--------|
| `best_model.onnx` | df832eaceb... | 9.299 B (header) |
| `best_model.onnx.data` | 7482611c34... | 5.597.184 B |
| `scaler.pkl` | b46e743cce... | 57.743 B |

Versión: v1.0.1 | Feature dim: 2381 | Formato: ONNX Opset 11

---

# 8. Pipeline de Extracción

## 8.1 PE Parsing

**Función:** `PEFeatureExtractor._parse_pe()`

**Estrategia en cascada:**

1. **PE_STRICT:** `pefile.PE(data=raw_data)` — parseo completo.
2. **PE_FASTLOAD:** `pefile.PE(data=raw_data, fast_load=True)` — tolera cabeceras malformadas.
3. **RAW_FALLBACK:** Si ambos fallan o archivo > 150 MB → solo features de bytes/strings.

**Optimización para archivos grandes (> 10 MB):** Solo se leen los primeros 10 MB para parseo de headers (suficiente para cabeceras PE).

## 8.2 String extraction

1. Muestreo distribuido si `len(raw_data) > 10 MB`.
2. Regex ASCII: `[\x20-\x7E]{4,}` sobre `scan_data`.
3. Si `num_strings > 5000`: muestreo híbrido (priorizar IoCs y strings largos).
4. Análisis de IoCs, histogramas de longitud/entropía, estadísticas de caracteres.

## 8.3 Entropy extraction

1. Muestreo distribuido si archivo > 10 MB.
2. Ventanas deslizantes 2048/1024 sobre datos muestreados.
3. Shannon entropy por ventana → histograma 256 bins [0, 8].

## 8.4 Feature vector generation

```python
# Orden de concatenación (CRÍTICO — debe coincidir con entrenamiento):
blocks = [
    ByteHistogram(),        # 256
    ByteEntropy(),          # 256
    StringExtractorBlock(), # 104
    GeneralFileInfo(),      # 10
    HeaderFileInfo(),       # 62
    SectionInfoBlock(),     # 255
    ImportsFeatureBlock(),  # 1280
    ExportsFeatureBlock()   # 128
]
# Total: 2381
```

Cada bloque fallido produce vector de ceros del tamaño correspondiente (tolerancia a fallos en cascada).

## 8.5 Validaciones

| Validación | Implementación |
|------------|---------------|
| Dimensión exacta | `assert len(vector) == 2381` |
| Sin NaN/Inf | Tests unitarios |
| Histogramas suman ≈ 1.0 | `np.isclose(sum, 1.0)` |
| Determinismo | Misma entrada → mismo vector (bitwise) |
| Diagnóstico post-extracción | `last_diagnostics` con modo, cobertura, packer |

---

# 9. Problemas Encontrados Durante el Desarrollo

## 9.1 Dataset EMBER desactualizado (V1)

| Aspecto | Detalle |
|---------|---------|
| **Causa raíz** | EMBER 2018 no refleja malware 2024-2026 |
| **Impacto** | Baja generalización a amenazas modernas |
| **Solución** | Migración a SOREL-20M + colección propia (100K muestras) |

## 9.2 Incompatibilidad con LIEF

| Aspecto | Detalle |
|---------|---------|
| **Causa raíz** | Librería `lief` con problemas de compatibilidad Python/rendimiento |
| **Impacto** | Extracción inestable en producción |
| **Solución** | Reescritura completa con `pefile` + arquitectura modular |

## 9.3 Malware empacado UPX evade ML

| Aspecto | Detalle |
|---------|---------|
| **Causa raíz** | El modelo analizaba el descompresor UPX (benigno), no el payload |
| **Impacto** | Falsos negativos en troyanos/gusanos empacados |
| **Solución** | Módulo `UPXUnpacker` en Fase 2 del pipeline híbrido |

## 9.4 Out-of-Memory en archivos gigantes

| Aspecto | Detalle |
|---------|---------|
| **Causa raíz** | `read_bytes()` completo en archivos de cientos de MB |
| **Impacto** | Crash del proceso, DoS por file bloating |
| **Solución** | Muestreo distribuido inicio-centro-final (10 MB máx.) |

## 9.5 Billion Strings Attack

| Aspecto | Detalle |
|---------|---------|
| **Causa raíz** | Regex sobre millones de strings ASCII de 4+ chars |
| **Impacto** | Minutos de CPU, agotamiento de RAM |
| **Solución** | `MAX_STRINGS=5000` + muestreo híbrido priorizando IoCs |

## 9.6 Entropy bombs / padding gigante

| Aspecto | Detalle |
|---------|---------|
| **Causa raíz** | Ventanas deslizantes sobre GB de padding → >500K ventanas |
| **Impacto** | Análisis de minutos por archivo |
| **Solución** | `MAX_ANALYSIS_BYTES=10MB` + muestreo distribuido |

## 9.7 PE corruptos / header mangling

| Aspecto | Detalle |
|---------|---------|
| **Causa raíz** | Malware modifica cabeceras PE intencionalmente |
| **Impacto** | Excepción en extractor → análisis abortado |
| **Solución** | PE_FASTLOAD + RAW_FALLBACK + relleno con ceros |

## 9.8 Carga lenta del modelo ONNX

| Aspecto | Detalle |
|---------|---------|
| **Causa raíz** | Recarga del modelo en cada request |
| **Impacto** | Latencia > 2 s en API |
| **Solución** | Patrón Singleton en `scan_service.get_engine()` |

## 9.9 Timeouts LLM

| Aspecto | Detalle |
|---------|---------|
| **Causa raíz** | Ollama con modelos grandes en hardware limitado |
| **Impacto** | API bloqueada esperando explicación |
| **Solución** | Timeout en `llm_service` + retorno de clasificación sin explicación |

## 9.10 Double Source of Truth (Auth)

| Aspecto | Detalle |
|---------|---------|
| **Causa raíz** | Frontend enviaba user_id mutable en body |
| **Impacto** | Riesgo de suplantación de identidad |
| **Solución** | Identidad 100% desde JWT Supabase en backend |

---

# 10. Mejoras de Robustez Implementadas

## A. Muestreo distribuido inicio-centro-final

| Aspecto | Detalle |
|---------|---------|
| **Problema** | File bloating: GB de ceros al final evaden análisis completo y causan OOM |
| **Solución** | `read_distributed_file()` y `get_distributed_sample()`: ⅓ inicio + ⅓ centro + ⅓ final, límite 10 MB |
| **Beneficio** | Memoria acotada; captura headers, código y overlay |
| **Impacto esperado** | Análisis estable en archivos > 150 MB sin crash |

## B. RAW_FALLBACK

| Aspecto | Detalle |
|---------|---------|
| **Problema** | PE corrupto → `pefile` falla → análisis abortado |
| **Solución** | Modo `RAW_FALLBACK`: extrae ByteHistogram, ByteEntropy, Strings + tamaño; resto = ceros |
| **Beneficio** | El pipeline nunca retorna error por parseo PE; el modelo recibe señal parcial |
| **Impacto esperado** | Cobertura del 100% de archivos enviados, con degradación documentada |

## C. Protección contra Billion Strings

| Aspecto | Detalle |
|---------|---------|
| **Problema** | Archivo con 500K+ strings → bucle O(n) con entropía por string |
| **Solución** | `MAX_STRINGS=5000`; priorizar strings > 64 chars y matches `REGEX_SUSPICIOUS` |
| **Beneficio** | Tiempo acotado; preserva IoCs críticos |
| **Impacto esperado** | Latencia estable < 100 ms en bloque strings |

## D. Protección contra Entropy Bombs

| Aspecto | Detalle |
|---------|---------|
| **Problema** | Archivo inflado genera >500K ventanas de entropía |
| **Solución** | `MAX_ANALYSIS_BYTES=10MB` con muestreo distribuido |
| **Beneficio** | ~10K ventanas máximo vs >500K |
| **Impacto esperado** | Bloque entropía: 200-300 ms vs minutos |

## E. Protección contra Padding Gigante

| Aspecto | Detalle |
|---------|---------|
| **Problema** | Overlay de megabytes de 0x00 al final del PE |
| **Solución** | Muestreo distribuido excluye padding homogéneo del análisis dominante |
| **Beneficio** | Histograma/entropía reflejan contenido real, no padding |
| **Impacto esperado** | Resistencia a evasión por inflado de tamaño |

## F. Fast PE Loading

| Aspecto | Detalle |
|---------|---------|
| **Problema** | Cabeceras PE malformadas rechazan parseo estricto |
| **Solución** | `pefile.PE(fast_load=True)` como segunda estrategia |
| **Beneficio** | Parseo parcial suficiente para headers/sections/imports |
| **Impacto esperado** | Mayor tasa de parseo exitoso en malware real |

## G. Protección contra PE corruptos

| Aspecto | Detalle |
|---------|---------|
| **Problema** | PE header mangling intencional |
| **Solución** | Cascada strict → fast → fallback; cada bloque con try/except individual |
| **Beneficio** | Degradación graceful documentada en `last_diagnostics` |
| **Impacto esperado** | Zero crashes por PE malformado |

## H. Límites de recursos

| Límite | Valor | Protege contra |
|--------|-------|---------------|
| Tamaño máximo parseo PE | 150 MB | DoS por tamaño |
| Bytes muestreados | 10 MB | OOM |
| Secciones analizadas | 96 | Section table flooding |
| DLLs importadas | 100 | Import table DoS |
| Funciones por DLL | 500 | Import stuffing |
| Exports | 500 | Export table DoS |
| Timeout UPX | 15 s | Hang en desempacado |
| Timeout YARA | 30 s | Reglas pathológicas |

## I. Telemetría y diagnósticos

**Estructura `last_diagnostics`:**

```json
{
  "diagnostics": {
    "file_size_bytes": 15728640,
    "bytes_sampled": 10485760,
    "percentage_analyzed": 66.67,
    "extraction_mode": "PE_FASTLOAD",
    "degradation_reason": "file_size_exceeded_10mb",
    "extraction_time_ms": 142.5,
    "packer_indicators": {
      "global_entropy": 7.45,
      "ratio_virtual_real": 3.2,
      "num_sections": 5,
      "rwx_sections": 1,
      "is_packed_upx": true,
      "packer_detected": true,
      "packer_reasons": ["upx_signature_in_bytes", "rwx_section_present"]
    }
  }
}
```

**Script de verificación:** `scripts/test_extractor_diagnostics.py`  
**Tests automatizados:** `tests/test_extractors.py` (RAW_FALLBACK, distributed sampling, packer detection)

---

# 11. Hallazgos Técnicos Más Importantes

# HALLAZGOS PRINCIPALES

## H1. La calidad del dataset supera al algoritmo

La migración de EMBER 2018 a SOREL-20M produjo mejoras de métricas **más significativas** que cualquier ajuste de hiperparámetros o cambio arquitectural (LightGBM → DNN). Confirmación empírica del principio *garbage in, garbage out*.

## H2. El packing UPX engaña al modelo ML pero no a YARA

Se observó que PEs empacados con UPX recibían scores benignos (~0.002) porque el modelo analizaba el stub de descompresión. La solución híbrida (desempacado previo + detección pasiva de packers) resolvió este vector de evasión específico.

## H3. Feature Hashing con SHA256 es suficiente

A pesar de colisiones teóricas en el hashing trick (Weinberger et al., 2009), SHA256 con 1280 dims para imports produce discriminación excelente (AUC 0.985). La redundancia del dataset compensa las colisiones.

## H4. El muestreo distribuido preserva señal discriminante

Contrario a la intuición inicial, analizar solo 10 MB (inicio+centro+final) de un archivo de 500 MB **no degrada significativamente** la detección porque headers PE, código e imports siempre residen al inicio del archivo.

## H5. RAW_FALLBACK es preferible a rechazar el archivo

Archivos no-PE o PE corruptos producen vectores parciales (768 dims de bytes+strings activas) que, aunque subóptimos, permiten al pipeline completarse y al backend clasificarlos como `suspicious` en lugar de `benign`.

## H6. La arquitectura modular aceleró iteraciones

Cada mejora de robustez (Billion Strings, entropy limits, distributed sampling) se implementó en el bloque afectado sin modificar el extractor principal, validando la inversión en Clean Architecture.

## H7. ONNX Runtime es 46× más ligero que PyTorch

La exportación ONNX reduce dependencias de ~700 MB a ~5 MB con inferencia comparable (< 15 ms vs ~20 ms), habilitando el empaquetado PyInstaller (~5.6 MB de pesos en `best_model.onnx.data`).

## Lecciones aprendidas

1. **Nunca confiar en parseo PE único:** siempre cascada con fallback.
2. **Limitar recursos explícitamente:** el malware explota la bondad del analista (DoS por tamaño/complejidad).
3. **Documentar degradación:** `extraction_mode` y `degradation_reason` son tan importantes como el score ML.
4. **Clasificar non-PE como suspicious, no benign:** un archivo no analizable ≠ seguro.

---

# 12. Evaluación de Robustez

## 12.1 Matriz de resistencia a técnicas de evasión

| Técnica de evasión | Estado | Mecanismo de mitigación | Residual |
|--------------------|--------|------------------------|----------|
| **Malware empaquetado (UPX)** | ✅ Mitigado | UPXUnpacker + detección pasiva | ⚠️ Packers custom (VMProtect, Themida) no desempacados |
| **Malware inflado (file bloating)** | ✅ Mitigado | Muestreo distribuido 10 MB | ⚠️ Señal parcial si payload está solo al final extremo |
| **PE corruptos / header mangling** | ✅ Mitigado | PE_FASTLOAD + RAW_FALLBACK | ⚠️ Features estructurales = 0 en fallback |
| **Strings flooding (Billion Strings)** | ✅ Mitigado | MAX_STRINGS=5000 + priorización IoC | ⚠️ IoCs ocultos en strings no priorizados pueden perderse |
| **Evasión por tamaño (>150 MB)** | ⚠️ Parcial | RAW_FALLBACK forzado, sin parseo PE | Análisis degradado a bytes+strings |
| **Entropy bombs** | ✅ Mitigado | MAX_ANALYSIS_BYTES=10 MB | ⚠️ Ataques sofisticados en región muestreada |
| **Import stuffing** | ⚠️ Parcial | Límites 100/500 + L1 normalization | Modelo puede ser influenciado por imports legítimos inyectados |
| **Overlay injection** | ⚠️ Parcial | Muestreo incluye final del archivo | Reducción artificial de entropía posible |
| **Polimorfismo estructural** | ⚠️ Parcial | ML generaliza patrones estadísticos | Variantes con estructura idéntica a benignos |
| **LotL / fileless** | ❌ No mitigado | — | Fuera de alcance estático |
| **Cifrado completo del PE** | ⚠️ Parcial | Alta entropía detectada como indicador | Clasificación depende del modelo, no determinista |

## 12.2 Ataques mitigados vs. posibles

**Mitigados con alta confianza:**

- OOM/DoS por tamaño de archivo.
- Billion strings / regex flooding.
- Entropy bomb computacional.
- UPX packing (con binario `upx` disponible).
- PE header mangling básico.
- Crash por PE irrecuperable.

**Siguen siendo posibles:**

- Packers/protectors no-UPX.
- Adversarial ML (perturbaciones optimizadas contra el modelo).
- Malware que imita estadísticamente software legítimo.
- Ataques fileless y en memoria.
- Payloads descargados en runtime (no presentes en disco).

---

# 13. Limitaciones Actuales

| Limitación | Descripción |
|------------|-------------|
| **Malware fileless** | PowerShell encoded, WMI, scripts en memoria — no analizable estáticamente |
| **Malware en memoria** | Inyección post-ejecución; módulo `BehavioralShield` en estado base |
| **Análisis dinámico** | No hay sandbox (Cuckoo/Frida) integrado |
| **Payloads remotos** | URLs detectadas como IoC, pero payload no descargado no se analiza |
| **Malware altamente polimórfico** | Si mutación preserva perfil estadístico benigno, evasión posible |
| **Formatos no-PE** | PDF, ELF, Java JAR, Office macros — fuera de alcance |
| **Packers custom** | Solo UPX desempacado automáticamente |
| **Dataset temporal** | SOREL-20M hasta 2020; drift de amenazas post-2020 |
| **Explicabilidad profunda** | SHAP no integrado en producción; LLM puede alucinar |
| **Pruebas con malware real** | Pendiente: sandbox aislado para validación in vivo (documentado en PROGRESS.md) |

---

# 14. Comparación Antes y Después de las Mejoras

| Dimensión | ANTES (Extractor V1 / pre-robustez) | DESPUÉS (Extractor V2 actual) |
|-----------|-----------------------------------|-------------------------------|
| **Robustez** | Crash en archivos > 50 MB; timeout en strings masivos; PE corrupto = error | Degradación graceful; límites explícitos; 3 modos de extracción |
| **Cobertura** | Solo PE parseable; non-PE rechazado | 100% archivos procesados (RAW_FALLBACK); non-PE → suspicious |
| **Riesgos** | DoS trivial por file bloating; OOM; análisis abortado silenciosamente | DoS mitigado; telemetría completa; UPX auto-unpack |
| **Latencia** | Indefinida (minutos posibles en archivos adversariales) | Acotada ~400 ms típico |
| **Observabilidad** | Sin diagnóstico post-extracción | `last_diagnostics` con modo, cobertura, packer, timing |
| **Pipeline** | ML estático único | Híbrido YARA → UPX → ML → (dynamic) |
| **Evasión UPX** | Falsos negativos frecuentes | Desempacado previo al ML |
| **Tests** | Validación dimensional básica | Suite adversarial: bloated, non-PE, UPX simulado |

---

# 15. Resultados Más Relevantes

# RESULTADOS CLAVE DEL PROYECTO

## R1. Métricas de clasificación (test set SOREL-20M)

| Métrica | Valor | Interpretación |
|---------|-------|---------------|
| **AUC-ROC** | **0.985** | Discriminación excelente |
| **FPR** | **< 0.5%** @ TPR=90% | Mínimas falsas alarmas en operación agresiva |
| **TPR** | **> 96%** @ FPR=1% | Alta detección con bajo ruido |
| **Accuracy** | > 98% | Exactitud global |

## R2. Rendimiento end-to-end

| Componente | Tiempo |
|------------|--------|
| I/O | 10–50 ms |
| Parsing PE | 50–100 ms |
| Análisis bytes/entropía | 200–300 ms |
| Strings + IoCs | 30–60 ms |
| Inferencia ONNX | **10–25 ms** |
| **Total** | **~400 ms** |

## R3. Reducción de fallos del extractor

| Escenario | Antes | Después |
|-----------|-------|---------|
| Archivo 15 MB inflado | OOM / timeout | 10 MB muestreados, ~140 ms |
| Archivo non-PE | Exception | RAW_FALLBACK, vector 2381 dims |
| PE corrupto | Exception | PE_FASTLOAD o RAW_FALLBACK |
| UPX packed | Score benigno (~0.002) | Desempacado → análisis del payload real |

## R4. Cobertura alcanzada

- **100%** de archivos enviados producen vector de 2381 dimensiones.
- **3 modos** de extracción documentados: PE_STRICT, PE_FASTLOAD, RAW_FALLBACK.
- **Pipeline híbrido** con 4 fases operativas.

## R5. Impacto sobre calidad del análisis

- Eliminación de crashes por evasión adversarial en tests automatizados (`tests/test_extractors.py`).
- Telemetría de packer integrada en resultados del engine (`result["details"]`).
- Clasificación tripartita (benign/suspicious/malicious) reduce falsas sensaciones de seguridad en non-PE.

---

# 16. Contribuciones del Proyecto

## 16.1 Aportes técnicos

1. **Extractor PE anti-evasión** con 9 mecanismos de protección documentados y testeados.
2. **Pipeline híbrido** YARA + UPX + DNN + LLM en arquitectura monorepo desacoplada.
3. **Aplicación desktop offline-first** con sincronización Supabase diferida.
4. **Telemetría de degradación** (`extraction_mode`, `percentage_analyzed`) integrada en resultados de escaneo.

## 16.2 Innovaciones implementadas

- Muestreo híbrido de strings con priorización de IoCs sobre muestreo uniforme.
- Detección pasiva multi-señal de packers (entropía, ratio virt/raw, RWX, UPX!, imports bajos).
- Clasificación tripartita con non-PE como `suspicious` (no `benign`).
- Singleton engine + ONNX para inferencia sub-segundo en API.

## 16.3 Diferenciadores respecto a proyectos académicos similares

| Aspecto | Proyectos académicos típicos | ShadowNet Defender |
|---------|------------------------------|-------------------|
| Despliegue | Notebook Jupyter + PyTorch | App desktop + ONNX + API REST |
| Robustez | Extracción ideal sobre PEs limpios | 9 protecciones anti-evasión |
| Explicabilidad | Métricas numéricas | LLM local (Ollama) + JSON estructurado |
| Pipeline | ML puro | Híbrido YARA + UPX + ML |
| Operación | Batch offline | Tiempo real + historial cloud + alertas n8n |

---

# 18. Conclusiones

ShadowNet Defender demuestra empíricamente la viabilidad de aplicar **Deep Learning sobre análisis estático de PE** para detección proactiva de malware, alcanzando **AUC-ROC de 0.985** con un pipeline reproducible alineado con SOREL-20M.

Las conclusiones técnicas principales son:

1. **El extractor robusto es tan crítico como el modelo.** Sin protecciones anti-evasión, un AUC de 0.985 en dataset limpio no se traduce en detección real frente a adversarios que explotan tamaño, strings y entropía.

2. **La arquitectura híbrida supera enfoques puros.** YARA captura lo conocido instantáneamente; UPX desempaca lo oculto; ML generaliza lo desconocido; LLM explica lo detectado.

3. **La exportación ONNX habilita despliegue real.** La transición PyTorch → ONNX Runtime elimina 695 MB de dependencias manteniendo inferencia < 25 ms.

4. **El análisis estático tiene límites inherentes** que motivan la Fase 4 (monitoreo conductual) y futuras integraciones con sandbox dinámico.

Desde la perspectiva académica, el proyecto contribuye un **caso de estudio completo** — desde dataset industrial hasta aplicación desktop — que cierra la brecha entre papers de detección estática y herramientas operativas para equipos SOC.

---

# 19. Apéndice Técnico

## 19.1 Estructura de carpetas

```
Shadownet_Defender_Extractor_V2/
├── backend/app/          # FastAPI: routes, services, schemas, integrations
├── configs/              # settings.py (umbrales, rutas modelo)
├── core/                 # engine.py, llm/, unpacking/, dynamic/, integrations/
├── docs/                 # PRD, PROGRESS, guías, schema SQL
├── extractors/           # 8 bloques FeatureBlock + extractor.py
├── frontend/             # React + Electron (pages, components, services)
├── models/               # best_model.onnx, scaler.pkl, model_manifest.json
├── requirements/         # Perfiles: base, ml, viz, dev (+ lockfiles)
├── samples/              # PEs de prueba (procexp64.exe)
├── scripts/              # Evaluación, diagnóstico, robustez, E2E
├── security/             # yara_scanner.py, yara_rules/*.yar
├── tests/                # pytest: extractors, LLM, n8n, CLI
├── tools/                # cli.py
├── utils/                # logger, runtime_checks
└── requirements.txt      # Perfil completo
```

## 19.2 Módulos principales

| Módulo | Archivo | Responsabilidad |
|--------|---------|-----------------|
| Motor | `core/engine.py` | Orquestación pipeline híbrido |
| Extractor | `extractors/extractor.py` | Agregación vector 2381 |
| Inferencia | `models/inference.py` | ONNX + scaler |
| YARA | `security/yara_scanner.py` | Firmas deterministas |
| UPX | `core/unpacking/__init__.py` | Detección/desempacado |
| LLM | `core/llm/explanation_service.py` | Explicaciones Ollama |
| API | `backend/app/main.py` | FastAPI + CORS |
| Scan | `backend/app/services/scan_service.py` | Clasificación tripartita |
| n8n | `core/integrations/n8n_client.py` | Webhooks SOC |

## 19.3 Dependencias principales

| Paquete | Versión mín. | Uso |
|---------|-------------|-----|
| pefile | ≥ 2023.2.7 | Parsing PE |
| numpy | ≥ 1.24 | Vectores |
| onnxruntime | ≥ 1.16 | Inferencia |
| scikit-learn | ≥ 1.3 | StandardScaler |
| pydantic | ≥ 2.0 | DTOs API |
| supabase | ≥ 2.0 | Auth + DB |
| openai | ≥ 1.0 | Cliente Ollama |
| torch | (ml.in) | Entrenamiento offline |

## 19.4 Scripts operativos

| Script | Función |
|--------|---------|
| `scripts/test_extractor_diagnostics.py` | Demo de modos extracción y packer |
| `scripts/test_robustness.py` | Ataques adversariales simulados |
| `scripts/evaluate_model_metrics.py` | Accuracy, Precision, Recall, AUC |
| `scripts/explain_global_model.py` | Permutation importance |
| `scripts/test_hybrid_pipeline.py` | UPX pack/unpack end-to-end |
| `scripts/verify_readiness.py` | Smoke test completo |
| `scripts/generate_mock_dataset.py` | Dataset sintético para evaluación |
| `scripts/e2e_test.py` | Test end-to-end API |
| `scripts/fix-ollama.sh` | Setup Ollama + modelo |

## 19.5 Casos de prueba

| Test | Archivo | Valida |
|------|---------|--------|
| Histograma suma 1.0 | `test_extractors.py::test_byte_histogram` | 256 dims normalizadas |
| Entropía suma 1.0 | `test_extractors.py::test_byte_entropy` | 256 dims normalizadas |
| RAW_FALLBACK non-PE | `test_extractors.py::test_raw_fallback_non_pe` | Modo + degradación |
| Muestreo distribuido | `test_extractors.py::test_distributed_sampling` | ≤ 10 MB muestreados |
| Detección UPX | `test_extractors.py::test_packer_detection` | Firma UPX! |
| LLM prompt | `test_llm_prompt_builder.py` | Estructura prompt |
| n8n client | `test_n8n_client.py` | Normalización eventos |

## 19.6 Endpoints API

| Método | Ruta | Función |
|--------|------|---------|
| GET | `/health` | Healthcheck |
| POST | `/scan/file` | Escaneo individual |
| POST | `/scan/multiple` | Escaneo batch |
| POST | `/analysis/explain` | Explicación LLM |

---

# 20. Resumen para Artículo Científico

## 20.1 Abstract (Resumen)

> **ShadowNet Defender** es un sistema de detección estática de malware para ejecutables Windows (PE) basado en aprendizaje profundo. El sistema transforma cada binario en un vector de **2.381 características** compatible con el estándar EMBER 2.0 / SOREL-20M, lo normaliza mediante Z-Score y lo clasifica con una red neuronal profunda (MLP: 2381→512→256→128→1) exportada a ONNX, alcanzando un **AUC-ROC de 0.985** sobre el benchmark SOREL-20M. Se implementa un **extractor robusto anti-evasión** con nueve mecanismos de protección — incluyendo muestreo distribuido, fallback de características crudas, límites anti-DoS y telemetría de degradación — que garantiza análisis estable frente a técnicas de file bloating, billion strings y PE corruptos. El pipeline híbrido combina detección por firmas YARA, desempacado UPX automático e inferencia ML, complementado con explicaciones generadas por LLM local (Ollama). El sistema se despliega como aplicación desktop offline-first con API REST, persistencia cloud (Supabase) y automatización SOC (n8n), demostrando la viabilidad de trasladar investigación académica en detección estática de malware a herramientas operativas.

## 20.2 Palabras clave

`Malware Detection` · `Static Analysis` · `Portable Executable` · `Deep Learning` · `SOREL-20M` · `Feature Engineering` · `ONNX` · `Adversarial Robustness` · `Explainable AI` · `YARA` · `Packing Detection`

## 20.3 Introducción preliminar

La detección de malware mediante firmas estáticas enfrenta limitaciones fundamentales ante técnicas de evasión modernas como polimorfismo, empaquetado y ataques zero-day. En respuesta, la comunidad científica ha adoptado enfoques basados en Machine Learning sobre características estáticas de ejecutables PE, con datasets masivos como EMBER (2018) y SOREL-20M (2020) que habilitan modelos con AUC-ROC superiores a 0.98. Sin embargo, la transición de experimentos de laboratorio a herramientas desplegables enfrenta desafíos adicionales: extractores frágiles ante técnicas adversariales de evasión, dependencias pesadas de frameworks de entrenamiento, y ausencia de explicabilidad para analistas humanos.

Este trabajo presenta **ShadowNet Defender**, un sistema integral que aborda estos desafíos mediante: (1) un extractor PE con protecciones anti-evasión documentadas y verificadas; (2) un pipeline híbrido que combina firmas YARA, desempacado UPX e inferencia DNN via ONNX Runtime; (3) explicabilidad asistida por LLM local; y (4) una arquitectura de software modular desplegada como aplicación desktop offline-first. Presentamos la ingeniería de características de 2.381 dimensiones, la arquitectura del modelo, las mejoras de robustez implementadas, y los resultados experimentales obtenidos sobre SOREL-20M.

## 20.4 Título científico propuesto

> **ShadowNet Defender: A Hybrid Static Malware Detection System with Adversarial-Robust Feature Extraction and Local Explainable AI for PE Executables**

*Alternativa en español:*

> **ShadowNet Defender: Sistema híbrido de detección estática de malware con extracción de características robusta ante evasión adversarial e inteligencia artificial explicable local para ejecutables PE**

---

*Documento generado como base técnica integral para artículo científico, trabajo de grado, paper académico, informe de ingeniería y memoria de investigación del proyecto ShadowNet Defender V2.*
