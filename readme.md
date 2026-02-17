# ShadowNet Defender: Extractor de Características de Malware (SOREL-20M)

![Version](https://img.shields.io/badge/version-1.0.0-blue) ![Python](https://img.shields.io/badge/python-3.8+-green) ![Features](https://img.shields.io/badge/features-2381-orange)

Este proyecto implementa un **extractor de características estáticas** para archivos PE (Portable Executable) de Windows, diseñado para ser **100% compatible** con el dataset **SOREL-20M** y la arquitectura de **EMBER 2.0**.

El objetivo es transformar cualquier archivo `.exe` o `.dll` en un vector numérico de **2381 dimensiones** que puede ser alimentado a modelos de Machine Learning (como LightGBM o XGBoost) para detectar malware.

---

## 🏗️ Arquitectura del Vector de Características

El vector de 2381 dimensiones se compone de 8 bloques de características, extraídos mediante análisis estático (sin ejecutar el archivo).

| Bloque              | Offset     | Dimensión | Descripción                                        | Implementado |
| :------------------ | :--------- | :-------: | :------------------------------------------------- | :----------: |
| **ByteHistogram**   | 0-255      |    256    | Frecuencia de cada byte (0x00-0xFF).               |      ✅      |
| **ByteEntropy**     | 256-511    |    256    | Histograma de entropía (complejidad) local.        |      ✅      |
| **StringExtractor** | 512-615    |    104    | Estadísticas y patrones en cadenas de texto.       |      ✅      |
| **GeneralFileInfo** | 616-625    |    10     | Tamaño, símbolos, debug info, etc.                 |      ✅      |
| **HeaderFileInfo**  | 626-687    |    62     | Cabeceras COFF y Optional, directorios de datos.   |      ✅      |
| **SectionInfo**     | 688-942    |    255    | Propiedades de secciones (.text, .data), entropía. |      ✅      |
| **Imports**         | 943-2222   |   1280    | Librerías importadas (Feature Hashing).            |      ✅      |
| **Exports**         | 2223-2350  |    128    | Funciones exportadas (Feature Hashing).            |      ✅      |
| **TOTAL**           | **0-2380** | **2381**  | Vector final concatenado.                          |   **100%**   |

---

## 🚀 Guía de Inicio Rápido

### 1. Instalación

```bash
# Clonar repositorio
git clone https://github.com/ShadowNet/Defender.git
cd Defender

# Crear entorno virtual
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
# (Dependencias clave: pefile, numpy, psutil, scikit-learn)
```

### 2. Uso Básico

```python
from core.features.extractor import PEFeatureExtractor

# Inicializar extractor
extractor = PEFeatureExtractor()

# Extraer features de un archivo
vector = extractor.extract("ruta/al/malware.exe")

print(f"Vector generado: {vector.shape}")
# Output: (2381,)
```

### 3. Validar Instalación

Ejecuta la suite de tests para asegurar que todo funciona correctamente:

```bash
# Validación completa (Output esperado: ✅ en todos los tests)
python verify_full_extractor.py

# Benchmark de rendimiento
python benchmark_extractor.py
```

---

## 🔬 Detalle Científico de los Bloques

### 1. ByteHistogram & ByteEntropy (Bytes Puros)

Analizan el archivo como una secuencia cruda de bytes, sin parsear estructura PE.

- **Histograma**: Detecta distribución de instrucciones. Malware suele tener distribuciones anómalas.
- **Entropía**: Mide "aleatoriedad". Entropía alta (>7.0) indica **empaquetado** o **cifrado**, muy común en malware para evadir firmas.

### 2. Imports & Exports (Feature Hashing)

Las funciones que un programa importa (ej: `CreateRemoteThread`, `InternetOpen`) definen su comportamiento.
Como existen millones de funciones posibles, usamos el **Hashing Trick**:

1.  String: `"kernel32:CreateFileA"`
2.  Hash: `SHA256("...")`
3.  Index: `Hash % 1280`
4.  Vector: `v[Index] += 1`

Esto permite representar un vocabulario infinito en un vector fijo.

### 3. StringExtractor (IoCs)

Extrae strings ASCII y busca Indicadores de Compromiso (IoCs):

- **Red**: URLs, IPs.
- **Rutas**: Rutas de sistema, PDB paths.
- **Comandos**: PowerShell, cmd.exe, claves de registro.

---

## 🛠️ Herramientas Incluidas

### `explain_prediction.py`

Analiza un archivo y muestra qué características son más prominentes (explicabilidad simple).

```bash
python explain_prediction.py samples/procexp.exe
```

**Salida ejemplo**:

```text
Indicadores de Strings (IoCs):
  ⚠️ Detectado URLs: 48
  ⚠️ Detectado IPs: 92
Entropía de Strings: 2.16 (Normal)
Imports: 538 funciones importadas mapeadas.
```

### `verify_full_extractor.py`

Verifica integridad matemática:

- No NaN/Inf.
- Suma de histogramas = 1.0.
- Shape estricto (2381,).

---

## 📦 Exportación y Producción

### Exportar a ONNX

Para usar el modelo entrenado en C++, C#, Java o JavaScript, se recomienda exportar a ONNX.

```python
# (Requiere skl2onnx)
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

initial_type = [('float_input', FloatTensorType([None, 2381]))]
onnx_model = convert_sklearn(sklearn_model, initial_types=initial_type)
with open("model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())
```

### Integración en Java

La lógica de extracción es determinística y reproducible.

1.  Usar parser PE (ej: GDA o librería propia).
2.  Implementar lógica de Hashing (SHA256 % N).
3.  Implementar lógica de Entropía (Shannon).
4.  Alimentar vector resultante a `OnnxRuntime` en Java.

---

## ⚠️ Errores Comunes

1.  **`pefile.PEFormatError`**: El archivo no es un ejecutable válido. El extractor devuelve un vector de ceros (silent fail) o lanza excepción según configuración.
2.  **Diferencias en Hashes**: Asegurarse de usar UTF-8, lowercasing y SHA256 estándar.
3.  **Rendimiento lento**: El cálculo de entropía deslizante es pesado en Python puro. Para producción masiva, se recomienda reimplementar ese bloque en C/Rust.

---

## 📚 Referencias

- **SOREL-20M Dataset**: Harang, R., & Rudd, E. M. (2020). SOREL-20M: A Large Scale Benchmark Dataset for Malicious PE Detection.
- **EMBER**: Anderson, H. S., & Roth, P. (2018). EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models.
- **Feature Hashing**: Weinberger, K., et al. (2009). Feature hashing for large scale multitask learning.

---

**ShadowNet Defender Team** - 2026
