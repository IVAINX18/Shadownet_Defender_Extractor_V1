# 🛡️ ShadowNet Defender (SND)

![License](https://img.shields.io/badge/license-MIT-blue) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Status](https://img.shields.io/badge/status-active-success) ![Dataset](https://img.shields.io/badge/dataset-SOREL--20M-orange) ![Model](https://img.shields.io/badge/model-LightGBM%2FONNX-green)

> **"Un sistema de defensa proactivo impulsado por Inteligencia Artificial y Análisis Estático Avanzado."**

ShadowNet Defender es una solución académica de ciberseguridad diseñada para cerrar la brecha entre el análisis de malware tradicional y las técnicas modernas de Deep Learning.

---

## 📖 Índice Completo

1.  [Visión General](#-visión-general)
2.  [Arquitectura del Sistema](#-arquitectura-del-sistema)
3.  [Ingeniería de Características en Profundidad](#-ingeniería-de-características-en-profundidad)
    - [Fundamentos Matemáticos](#fundamentos-matemáticos)
    - [1. Byte Histogram (256 dims)](#1-byte-histogram-256-dims)
    - [2. Byte Entropy (256 dims)](#2-byte-entropy-256-dims)
    - [3. Strings & IoCs (104 dims)](#3-strings--ioc-metrics-104-dims)
    - [4. General & Header Info (72 dims)](#4-general--header-info-72-dims)
    - [5. Section Info (255 dims)](#5-section-info-255-dims)
    - [6. Imports & Exports Hashing (1408 dims)](#6-imports--exports-hashing-1408-dims)
4.  [Dataset SOREL-20M: Análisis](#-dataset-sorel-20m-análisis)
5.  [Pipeline de Machine Learning](#-pipeline-de-machine-learning)
6.  [Estructura del Proyecto y Módulos](#-estructura-del-proyecto-y-módulos)
7.  [Guía de Instalación y Uso](#-guía-de-instalación-y-uso)
8.  [Resultados, Benchmarks y Limitaciones](#-resultados-benchmarks-y-limitaciones)
9.  [Hoja de Ruta: IA Generativa y UI](#-hoja-de-ruta-ia-generativa-y-ui)
10. [Aspectos Éticos y Legales](#-aspectos-éticos-y-legales)
11. [Referencias Académicas](#-referencias-académicas)

---

## 👁️ Visión General

**ShadowNet Defender (SND)** nace como respuesta a la creciente sofisticación del malware moderno. Los atacantes utilizan técnicas automatizadas de ofuscación (polimorfismo, empaquetado personalizado) para generar miles de variantes únicas de un mismo malware diariamente, haciendo ineficaces los antivirus basados en firmas estáticas (MD5/SHA256).

### 🎯 El Problema: La Asimetría de la Ciberdefensa

Los defensores deben bloquear el 100% de los ataques, mientras que al atacante le basta con tener éxito una sola vez. Los sistemas tradicionales fallan ante:

- **Malware Zero-Day**: Amenazas nunca antes vistas.
- **Ransomware Polimórfico**: Variantes que cambian su hash en cada infección.
- **Ataques "Living off the Land"**: Uso de herramientas legítimas (PowerShell) con fines maliciosos.

### 💡 La Solución: Detección Basada en Comportamiento Estático

SND no ejecuta el archivo (evitando riesgos de infección en el análisis), sino que lo "radiografía". Utiliza un modelo de **Gradient Boosting (LightGBM)** entrenado con ~~20 millones~~ de muestras para aprender patrones abstractos de malicia.

El sistema detecta anomalías sutiles:

- ¿Por qué una calculadora necesita importar funciones de encriptación?
- ¿Por qué el 90% del archivo tiene una entropía máxima (encriptado)?
- ¿Por qué no tiene interfaz gráfica pero importa funciones de teclado (keylogger)?

---

## 🏗️ Arquitectura del Sistema

El proyecto sigue una estricta arquitectura por capas inspirada en principios de **Clean Architecture**, asegurando que la lógica de extracción, el modelo y la interfaz estén desacoplados.

```mermaid
graph TD
    subgraph "Nivel 1: Entrada"
        A[Archivo PE Desconocido] -->|Stream de Bytes| B(Feature Extractor Engine);
    end

    subgraph "Nivel 2: Extracción (CPU Bound)"
        B --> C{Byte Analyzer};
        B --> D{PE Parser / pefile};
        C -->|Histogram & Entropy| E[Raw Features];
        D -->|Headers, Sections, Strings| E;
        D -->|Imports, Exports| F[Hasher Engine];
        F -->|Hashed Features| E;
    end

    subgraph "Nivel 3: Inferencia (AI Core)"
        E -->|Vector 2381-d| G[StandardScaler];
        G -->|Normalización (Array NumPy)| H[Modelo ONNX (LightGBM)];
        H -->|Cálculo de Probabilidad| I(Score [0.0 - 1.0]);
    end

    subgraph "Nivel 4: Decisión y Reporte"
        I --> J{Umbral de Decisión};
        J -->|Score > 0.85| K[🔴 MALWARE (High Confidence)];
        J -->|0.50 < Score <= 0.85| L[🟠 MALWARE (Medium Confidence)];
        J -->|Score <= 0.50| M[🟢 BENIGN];
    end
```

### Componentes Clave

1.  **Core Engine (`core/engine.py`)**: Orquestador principal. Carga modelos, gestiona errores y tiempos.
2.  **Extractors (`extractors/`)**: Módulos independientes. Cada uno implementa la interfaz `FeatureBlock`. Si falla uno (e.g., cabecera corrupta), los demás siguen funcionando.
3.  **ONNX Runner (`models/inference.py`)**: Abstracción sobre `onnxruntime`. Permite cambiar el modelo subyacente sin tocar el código de la aplicación.

---

## 🧩 Ingeniería de Características en Profundidad

El extractor convierte un binario complejo en un vector de **2381 números flotantes**. Este diseño es totalmente compatible con el estándar **EMBER 2.0 / SOREL-20M**.

### Fundamentos Matemáticos

#### Normalización (Z-Score)

Los modelos de ML funcionan mejor cuando los datos tienen escalas similares. Aplicamos:
$$ z = \frac{x - \mu}{\sigma} $$
Donde $\mu$ es la media y $\sigma$ la desviación estándar calculada sobre el dataset de entrenamiento (SOREL-20M).

#### Feature Hashing (The Hashing Trick)

Para vectorizar datos categóricos de vocabulario abierto (nombres de librerías), usamos hashing. Esto reduce la dimensionalidad y colisiones controladas.
$$ \phi(x) = \text{hash}(x) \pmod d $$
Donde $d$ es la dimensión del vector destino (1280 para imports).

---

### 1. Byte Histogram (256 dims)

Representa la frecuencia de aparición de cada byte posible (0-255).

- **Fórmula**: $H[i] = \frac{\text{count}(byte_i)}{\text{total\_bytes}}$
- **Utilidad**: Detecta ofuscación. Los ejecutables normales tienen picos en bytes correspondientes a instrucciones comunes (`0x00` padding, `0xC3` ret). El malware encriptado tiende a una distribución uniforme ("ruido blanco").

### 2. Byte Entropy (256 dims)

Calcula la **Entropía de Shannon** usando una ventana deslizante de 2048 bytes con un paso (stride) de 1024 bytes.
$$ H(X) = - \sum\_{i=0}^{255} p_i \log_2 p_i $$
El resultado es un histograma de entropías:

- **Eje X (Bins)**: Niveles de entropía (de 0.0 a 8.0 bits/byte).
- **Valor**: Proporción del archivo que tiene esa entropía.
- **Interpretación**: Si la mayoría del archivo tiene entropía ~8.0, está empaquetado o comprimido.

### 3. Strings & IoC Metrics (104 dims)

Análisis de cadenas extraídas con el comando `strings` (ASCII).

- **Estadísticas**: Longitud promedio, número de strings, entropía promedio.
- **Histogramas**: Distribución de longitudes de strings.
- **IoC (Regex Match)**:
  - Rutas sospechosas (`C:\Temp`, `AppData`).
  - URLs (`http://`, `.onion`).
  - Registros (`HKEY_LOCAL_MACHINE`).
  - 'MZ' embebidos (indica otro ejecutable oculto dentro del archivo -> Dropper).

### 4. General & Header Info (72 dims)

Metadatos extraídos directamente del `IMAGE_FILE_HEADER` y `IMAGE_OPTIONAL_HEADER`.

- **Timestamp**: Fecha de compilación (útil, aunque falsificable).
- **Machine**: Arquitectura (x86, x64).
- **ImageBase**: Dirección de memoria preferida.
- **Subsystem**: GUI, Consola, Driver nativo. (Malware suele ser Consola o GUI invisible).

### 5. Section Info (255 dims)

Análisis profundo de secciones (`.text`, `.data`, `.rsrc`, etc.).

- **Nombres Hashed**: Se hace hash de los nombres de sección. Malware usa nombres no estándar (e.g., `.upx0`, `.cryp`).
- **Propiedades**: Tamaño virtual vs Tamaño en disco.
- **Flags**: ¿Es la sección ejecutable y escribible a la vez (`RWX`)? Esto es una **bandera roja** enorme, típica de malware auto-modificable o polimórfico.

### 6. Imports & Exports Hashing (1408 dims)

Aquí reside gran parte del poder predictivo.

- **Imports (1280 dims)**: Funciones que el malware "pide" al sistema operativo.
  - _Ejemplo_: `kernel32.dll:WriteProcessMemory` (Inyección de código).
  - _Ejemplo_: `urlmon.dll:URLDownloadToFile` (Downloader).
- **Exports (128 dims)**: Funciones que el archivo ofrece (común en DLLs maliciosas o payloads de ataque lateral).

Se usa hashing **SHA-256** truncado y módulo N para mapear estas funciones al vector.

---

## 💾 Dataset SOREL-20M: Análisis

**SOREL-20M** es un hito en la investigación de seguridad académica.

- **Tamaño**: ~8 Terabytes de binarios (reducidos a features extraídos).
- **Etiquetas**: Metadatos de detección de múltiples motores comerciales (agregación tipo VirusTotal).
- **Temporalidad**: Muestras recolectadas entre 2017 y 2019, permitiendo evaluar la capacidad de generalización temporal del modelo.

### ¿Por qué no EMBER?

Aunque EMBER es excelente, SOREL es más grande y su esquema de etiquetado es más robusto para diferenciar entre _Adware_, _Ransomware_ y _Spyware_, lo que permitirá en el futuro (Fase 2 del proyecto) clasificación multiclase.

---

## 🧠 Pipeline de Machine Learning

### Modelo: LightGBM (Gradient Boosting Machine)

Elegido sobre redes neuronales profundas por:

1.  **Eficiencia en datos tabulares**: GBDT (Gradient Boosted Decision Trees) sigue siendo el estado del arte para vectores de características fijas.
2.  **Inferencia rápida**: Ideal para escaneo en tiempo real.
3.  **Interpretabilidad**: Permite calcular la "importancia de características" (Feature Importance), crucial para explicar por qué se detectó un archivo.

### Exportación a ONNX

El modelo se entrena en Python (scikit-learn/LightGBM) y se congela en ONNX.

- **Independencia**: No se necesita instalar `lightgbm` en el cliente final, solo `onnxruntime` (más ligero).
- **Interoperabilidad**: El mismo archivo `.onnx` puede cargarse en una futura UI hecha en C#, Java o C++.

---

## 📂 Estructura del Proyecto y Módulos

Una explicación detallada para desarrolladores o investigadores que deseen extender el proyecto.

```
shadownet/
├── configs/             # Configuraciones centralizadas (paths, umbrales)
├── core/                # Lógica de negocio
│   ├── engine.py        # Clase ShadowNetEngine (Facade principal)
│   └── pipeline.py      # Definición de pasos de transformación
├── extractors/          # Lógica de extracción (Extensible)
│   ├── base.py          # Interfaz abstracta (FeatureBlock)
│   ├── byte_hist.py     # Implementación histograma
│   ├── string_extractor.py # Implementación strings
│   └── ...              # Resto de extractores
├── models/              # Gestión de modelos
│   ├── inference.py     # ShadowNetModel (Manejo de ONNX Session)
│   ├── model_loader.py  # Carga segura y validación de hashes de modelos
│   └── scaler.pkl       # Objeto de normalización pre-entrenado
├── utils/               # Utilidades transversales
│   ├── logger.py        # Logging profesional con 'rich'
│   └── file_ops.py      # Manejo seguro de archivos
├── samples/             # Archivos de prueba (e.g., procexp64.exe)
├── tests/               # Suite de tests automáticos
└── legacy/              # Código archivado de versiones anteriores
```

---

## ⚙️ Guía de Instalación y Uso

### Entorno Recomendado

- **OS**: Linux (Ubuntu 22.04+)
- **Python**: 3.10+
- **RAM**: 4GB+ (para inferencia), 16GB+ (si se planea re-entrenar).

### Paso a Paso

1.  **Clonado y Entorno Virtual**:

    ```bash
    git clone https://github.com/IVAINX18/Shadownet_Defender.git
    cd Shadownet_Defender

    # Crear entorno virtual para aislar dependencias
    python3 -m venv .venv

    # Activar entorno
    source .venv/bin/activate
    ```

2.  **Instalación de Dependencias**:
    Utilizamos versiones fijas (`==`) en `requirements.txt` para garantizar reproducibilidad.

    ```bash
    pip install -r requirements.txt
    ```

3.  **Verificación de Integridad**:
    Ejecuta el script de diagnóstico para asegurar que el modelo y los extractores funcionan.

    ```bash
    python verify_refactor.py
    ```

4.  **Escaneo Personalizado**:
    Crea un script Python simple (`scan.py`):

    ```python
    from core.engine import ShadowNetEngine

    # Inicializar motor (carga modelo ONNX en memoria)
    engine = ShadowNetEngine()

    # Escanear ruta
    resultado = engine.scan_file("/ruta/a/archivo_sospechoso.exe")

    # Mostrar resultado JSON
    import json
    print(json.dumps(resultado, indent=4))
    ```

---

## 📊 Resultados, Benchmarks y Limitaciones

### Rendimiento (Benchmark en i7-12700H)

| Operación              | Tiempo Promedio | Notas                                      |
| :--------------------- | :-------------- | :----------------------------------------- |
| Carga de Modelo        | 150ms           | Solo ocurre una vez al inicio.             |
| Extracción de Features | 350-600ms       | Depende del tamaño del archivo. I/O Bound. |
| Inferencia (ONNX)      | 15-30ms         | Extremadamente rápido. CPU Bound.          |
| **Total por archivo**  | **~0.5s**       | Apto para escaneo en tiempo real.          |

### Limitaciones Conocidas

1.  **Packers Exóticos**: Si un malware usa un packer comercial muy novedoso que comprime absolutamente todo (incluyendo headers), la extracción puede fallar o dar poca información.
2.  **Archivos .NET / Go**: El extractor actual está optimizado para binarios C/C++ (PE nativo). Binarios .NET pueden requerir features adicionales.
3.  **Adversarial Attacks**: Es teóricamente posible modificar un malware (añadiendo secciones "buenas" o strings benignos) para engañar al modelo.

---

## 🔮 Hoja de Ruta: IA Generativa y UI

### Fase 2: Integración LLM (Q3 2026)

El objetivo es pasar de una "Caja Negra" (Score 0.99) a una "Caja de Cristal".
Integraremos un modelo **LLM Pequeño (SLM)** como _TinyLlama_ o _Phi-3_ localmente.

**Flujo propuesto**:

1.  ShadowNet detecta malware.
2.  Se identifican los features que más contribuyeron a la decisión (usando SHAP values).
    - _Ej: Importa `SetWindowsHookEx`, Sección `.text` escribible._
3.  Se construye un prompt para el LLM:
    - _"Analiza estos indicadores técnicos y explica a un usuario no experto qué riesgo suponen."_
4.  El LLM genera un reporte ejecutivo.

### Fase 3: Interfaz Gráfica (UI)

Desarrollo de una aplicación de escritorio moderna.

- **Tecnología**: Custom Tkinter o Flet (Python) para mantener el stack unificado.
- **Funciones**: Drag & Drop, historial de escaneos, visualización gráfica de entropía.

---

## ⚖️ Aspectos Éticos y Legales

Este software ha sido desarrollado con fines **estrictamente académicos y defensivos**.

- **No contiene malware**: El repositorio no distribuye muestras maliciosas. Los tests usan archivos benignos o "dummy files".
- **Uso Responsable**: El autor no se hace responsable del uso de esta herramienta en entornos críticos sin la debida validación adicional.
- **Privacidad**: Todo el análisis es **local**. Ningún archivo sale del equipo del usuario hacia la nube.

---

## 📚 Referencias Académicas

Para profundizar en la ciencia detrás de ShadowNet:

1.  **SOREL-20M Paper**: Harang, R., & Rudd, E. M. (2020). _SOREL-20M: A Large Scale Benchmark Dataset for Malicious PE Detection_. arXiv:2012.07633.
2.  **Dataset EMBER**: Anderson, H. S., & Roth, P. (2018). _EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models_. arXiv:1804.04637.
3.  **Feature Hashing**: K. Weinberger, et al. (2009). _Feature Hashing for Large Scale Multitask Learning_. ICML.
4.  **Adversarial ML**: Goodman, D., et al. (2020). _AdvBox: A Toolbox to Generate Adversarial Examples that Fool Neural Networks_.

---

### 👨‍💻 Autor y Contacto

**Desarrollado por:** IVAINX y VANkLEis
**Rol:** Estudiantes de Ingeniería en Sistemas & Investigadores de INNOVASIC
**Año:** 2026
**Licencia:** ShadowNet License

---

_Hecho con ❤️ y ☕ para hacer de Internet un lugar más seguro._
