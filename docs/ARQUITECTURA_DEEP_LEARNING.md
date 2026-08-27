# Arquitectura de Deep Learning y Redes Neuronales en ShadowNet Defender

Este documento explica de forma **técnica pero clara, estructurada y accesible** cómo está diseñado el sistema de Deep Learning e Inteligencia Artificial dentro de **ShadowNet Defender**.

---

## 1. Visión General: El Rol de la Inteligencia Artificial

ShadowNet Defender combina el análisis estático tradicional con **Deep Learning (Aprendizaje Profundo)** e **IA Generativa**. 

En lugar de depender exclusivamente de firmas estáticas (hashes) o reglas manuales que los atacantes pueden evadir fácilmente cambiando un solo byte, el sistema aprende a **reconocer los patrones estructurales, matemáticos y de comportamiento** del malware.

```mermaid
flowchart LR
    A[📁 Archivo PE .exe/.dll] --> B[🔬 Extractor 2381-dim]
    B --> C[⚙️ Normalizador Z-Score]
    C --> D[🧠 Red Neuronal MLP ONNX]
    D --> E[📊 Score P Malware]
    E --> F[🤖 LLM / Ollama Transformer]
    F --> G[📋 Reporte Explicativo XAI]
```

---

## 2. Deep Learning en el Proyecto

### 📌 ¿Qué se usa?
El subsistema de Deep Learning abarca componentes de código, artefactos pre-entrenados y servicios de inferencia:

1. **Artefactos del Modelo (`models/`):**
   - `best_model.onnx` y `best_model.onnx.data`: Red neuronal entrenada y optimizada para producción (~5.6 MB de pesos).
   - `scaler.pkl`: Objeto `StandardScaler` con los parámetros de media ($\mu$) y desviación estándar ($\sigma$) para 2,381 dimensiones.
   - `model_manifest.json`: Registro oficial de versión (`v1.0.1`), umbrales e integridad mediante hashes SHA-256.

2. **Motores de Inferencia y Explicabilidad (`models/inference.py`, `core/`):**
   - `models/inference.py`: Ejecución de inferencia ligera con `onnxruntime`.
   - `core/explainers/shap_explainer.py`: Algoritmo SHAP para auditoría de características.
   - `core/llm/`: Servicio de integración con Ollama (modelos Transformer).

3. **Dataset y Pipeline de Entrenamiento (Histórico):**
   - Entrenado en PyTorch con GPU NVIDIA A100 sobre un dataset de **5.1 millones de muestras** (5M de SOREL-20M + 100K muestras *in-the-wild* 2024–2026).

---

### 💡 ¿Por qué se usa?
- **Detección Zero-Day:** El modelo no memoriza nombres ni hashes; aprende representaciones latentes abstractas del malware.
- **Portabilidad y Rendimiento:** PyTorch requiere librerías pesadas (~700 MB) y GPU. Exportar a **ONNX Runtime** reduce la huella a **~5 MB** y logra inferencias en **< 15 ms** utilizando únicamente la CPU.
- **Superación de Métodos Previos:** En la versión V2 se usaba *LightGBM* (árboles de decisión). La migración en V3/V4 a una Red Neuronal Profunda (DNN) mejoró la capacidad de generalización y redujo los falsos positivos en software legítimo complejo.

---

### ⚙️ ¿Cómo se usa?
1. **Extracción:** Al recibir un binario, `PEFeatureExtractor` genera un vector crudo de 2381 dimensiones.
2. **Estandarización:** Se aplica `scaler.pkl` para normalizar los valores al rango esperado ($Z = \frac{x - \mu}{\sigma}$).
3. **Inferencia ONNX:** El vector normalizado entra a `best_model.onnx` vía `onnxruntime.InferenceSession`.
4. **Veredicto:** El modelo retorna una probabilidad continua entre `0.0` (Benigno) y `1.0` (Malware).

---

## 3. Red Neuronal Principal: Perceptrón Multicapa (MLP / DNN)

### 📌 ¿Qué se usa?
La arquitectura principal es un **Perceptrón Multicapa (MLP)** o Red Neuronal Feedforward Profunda con topología en "embudo cónico" (*funnel architecture*).

#### Composición del Vector de Entrada (2381 Dimensiones):
- **Histograma de Bytes (256 dims):** Frecuencia estadística de bytes `0x00` a `0xFF`.
- **Entropía de Bytes (256 dims):** Medición de desorden local con ventana deslizante de 2048 bytes.
- **Strings e IoCs (104 dims):** Patrones de URLs, comandos PowerShell, rutas de registro, claves criptográficas.
- **Metadatos Generales PE (10 dims):** Tamaños, número de secciones, flags generales.
- **Cabeceras PE (62 dims):** Campos de COFF Header, Optional Header y Data Directories.
- **Análisis de Secciones (255 dims):** Permisos RWX, nombres, entropía por sección y discrepancias VirtualSize/RawSize.
- **Imports IAT (1280 dims):** Feature Hashing con SHA-256 de las funciones importadas.
- **Exports (128 dims):** Feature Hashing de funciones exportadas.

#### Estructura de la Red Neuronal:
```text
Entrada (2381 neuronas - Vector Z-Score)
   │
   ▼
[Capa Oculta 1] ── Dense(512) ──► BatchNorm1d ──► ReLU ──► Dropout(p=0.3)
   │
   ▼
[Capa Oculta 2] ── Dense(256) ──► BatchNorm1d ──► ReLU ──► Dropout(p=0.2)
   │
   ▼
[Capa Oculta 3] ── Dense(128) ──► BatchNorm1d ──► ReLU ──► Dropout(p=0.1)
   │
   ▼
[Capa Salida]   ── Dense(1)   ──► Sigmoid ──► Score P(Malware) ∈ [0.0, 1.0]
```

---

### 💡 ¿Por qué se usa?
- **Adecuación al tipo de datos:** Las características extraídas son numéricas y tabulares. Las redes MLP son la arquitectura estándar en la literatura científica para este tipo de representaciones (como en los benchmarks EMBER y SOREL-20M).
- **Batch Normalization (`BatchNorm1d`):** Estabiliza y acelera el aprendizaje al normalizar las activaciones internas de cada mini-batch.
- **Activación `ReLU`:** Evita el problema del gradiente evanescente (*vanishing gradient*) y mantiene alta eficiencia computacional.
- **`Dropout` Progresivo (0.3 → 0.2 → 0.1):** Desactiva aleatoriamente neuronas durante el entrenamiento. Al ser mayor cerca de la entrada y menor cerca de la salida, evita que la red dependa en exceso de características específicas (previene *overfitting*).
- **`Sigmoid` en la Salida:** Transforma la salida final en un valor entre $0$ y $1$, directamente interpretable como probabilidad matemática.

---

### ⚙️ ¿Cómo se usa?
La red procesa la información de forma secuencial hacia adelante (*forward pass*):
1. Recibe las 2381 entradas escaladas.
2. La **Capa 1** (512 neuronas) extrae combinaciones iniciales de bajo nivel.
3. La **Capa 2** (256 neuronas) comprime la representación a patrones de nivel medio (ej. combinaciones de imports sospechosos + entropía alta).
4. La **Capa 3** (128 neuronas) sintetiza las señales en conceptos abstractos de amenaza.
5. La **Capa de Salida** emite la probabilidad final en $< 15\text{ ms}$.

---

## 4. Red Neuronal Secundaria: Arquitectura Transformer (LLM)

### 📌 ¿Qué se usa?
Integración con modelos de lenguaje generativos (*Large Language Models*) basados en la arquitectura **Transformer**, ejecutados localmente mediante **Ollama** (ej. `llama3.2:3b`, `mistral-7b`).

---

### 💡 ¿Por me se usa?
- **Explicabilidad Forense (XAI):** Un score numérico como `0.982` indica la maliciosidad, pero un analista de seguridad necesita comprender **por qué** se tomó esa decisión.
- **Traducción Contextual:** El LLM recibe los metadatos del binario y los valores **SHAP** (que indican qué características pesaron más en el veredicto) y redacta un reporte claro en lenguaje natural con recomendaciones de remediación.

---

### ⚙️ ¿Cómo se usa?
1. Se calcula la predicción del MLP y los valores SHAP correspondientes.
2. `prompt_builder.py` construye una plantilla con la información forense recopilada.
3. `OllamaClient` envía el prompt mediante la API compatible con OpenAI a Ollama local.
4. El LLM devuelve un diagnóstico estructurado en JSON con el resumen del comportamiento y las acciones recomendadas.

---

## 5. Resumen Comparativo de Redes Neuronales

| Aspecto | Red Principal (MLP / DNN) | Red Secundaria (Transformer / LLM) |
| :--- | :--- | :--- |
| **Tipo de Arquitectura** | Perceptrón Multicapa Feedforward | Transformer Autoregresivo |
| **Rol en el Sistema** | Clasificación rápida y objetiva de malware | Explicabilidad (XAI) y reporte narrativo |
| **Entrada** | Vector numérico de 2381 dimensiones | Prompt estructurado (Texto + Metadatos + SHAP) |
| **Salida** | Probabilidad cuantitativa $P(\text{Malware}) \in [0.0, 1.0]$ | Diagnóstico explicativo en lenguaje natural |
| **Runtime / Motor** | `onnxruntime` (CPU) | `Ollama` / API local |
| **Tiempo de Inferencia** | $< 15\text{ ms}$ | $1.5\text{ s} - 4.0\text{ s}$ (dependiendo del hardware) |

---

> 📝 **Nota sobre Mantenimiento:** Los artefactos del modelo ONNX y el escalador Z-Score se encuentran verificados y congelados en la versión `v1.0.1`. Toda modificación a la arquitectura o reentrenamiento debe registrarse en `models/model_manifest.json`.
