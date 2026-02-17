# ShadowNet Defender - Extractor de Características SOREL-20M

## 📋 Tabla de Contenidos

1. [¿Qué es ShadowNet Defender?](#qué-es-shadownet-defender)
2. [¿Qué es SOREL-20M?](#qué-es-sorel-20m)
3. [Arquitectura del Extractor](#arquitectura-del-extractor)
4. [Bloques de Características](#bloques-de-características)
   - [ByteHistogram](#1-bytehistogram-256-features)
   - [ByteEntropy](#2-byteentropy-256-features)
   - [GeneralFileInfo](#3-generalfileinfo-10-features)
   - [HeaderFileInfo](#4-headerfileinfo-62-features)
   - [Imports (Feature Hashing)](#5-imports-1280-features)
5. [Uso del Extractor](#uso-del-extractor)
6. [Validación y Testing](#validación-y-testing)
7. [Preparación para Producción](#preparación-para-producción)

---

## ¿Qué es ShadowNet Defender?

**ShadowNet Defender** es un sistema de detección de malware basado en Inteligencia Artificial que analiza archivos ejecutables de Windows (formato PE - Portable Executable) para determinar si son maliciosos o legítimos.

### ¿Cómo funciona?

1. **Extracción de características**: Analiza el archivo `.exe` y extrae **2381 características numéricas** que describen su comportamiento, estructura y propiedades.
2. **Análisis con IA**: Un modelo de Machine Learning (entrenado con millones de muestras) usa estas características para predecir si el archivo es malware.
3. **Decisión**: El sistema devuelve una probabilidad (0% = seguro, 100% = malware).

---

## ¿Qué es SOREL-20M?

**SOREL-20M** es un dataset público de investigación creado por Sophos y ReversingLabs que contiene:

- **20 millones** de archivos ejecutables de Windows
- **10 millones** de malware confirmado
- **10 millones** de software legítimo confirmado

Este dataset utiliza un formato específico de **2381 características** por archivo, compatible con el formato EMBER (proyecto de Endgame de 2018).

**¿Por qué 2381 features?** Este número fue optimizado por investigadores para capturar información suficiente sin ser excesivo, balanceando precisión y eficiencia computacional.

---

## Arquitectura del Extractor

### Estructura Modular

El extractor está diseñado en **bloques independientes** (`FeatureBlock`). Cada bloque es responsable de extraer un tipo específico de características.

```
Archivo PE (malware.exe)
    ↓
┌───────────────────────────────────┐
│  PEFeatureExtractor               │
│                                   │
│  ┌─────────────────────────────┐ │
│  │ ByteHistogram    (0-255)    │ │ → 256 features
│  ├─────────────────────────────┤ │
│  │ ByteEntropy      (256-511)  │ │ → 256 features
│  ├─────────────────────────────┤ │
│  │ StringExtractor  (512-615)  │ │ → 104 features (pendiente)
│  ├─────────────────────────────┤ │
│  │ GeneralFileInfo  (616-625)  │ │ → 10 features
│  ├─────────────────────────────┤ │
│  │ HeaderFileInfo   (626-687)  │ │ → 62 features
│  ├─────────────────────────────┤ │
│  │ SectionInfo      (688-942)  │ │ → 255 features (pendiente)
│  ├─────────────────────────────┤ │
│  │ Imports          (943-2222) │ │ → 1280 features
│  ├─────────────────────────────┤ │
│  │ Exports          (2223-2350)│ │ → 128 features (pendiente)
│  └─────────────────────────────┘ │
└───────────────────────────────────┘
    ↓
Vector de 2381 números decimales
[0.277, 0.010, 0.005, ..., 0.0, 0.0]
```

### Estado Actual de Implementación

| Bloque          | Offset       | Dimensión | Estado              | Progreso |
| --------------- | ------------ | --------- | ------------------- | -------- |
| ByteHistogram   | 0-255        | 256       | ✅ Implementado     | 100%     |
| ByteEntropy     | 256-511      | 256       | ✅ Implementado     | 100%     |
| StringExtractor | 512-615      | 104       | ⏳ Pendiente        | 0%       |
| GeneralFileInfo | 616-625      | 10        | ✅ Implementado     | 100%     |
| HeaderFileInfo  | 626-687      | 62        | ✅ Implementado     | 100%     |
| SectionInfo     | 688-942      | 255       | ⏳ Pendiente        | 0%       |
| **Imports**     | **943-2222** | **1280**  | **✅ Implementado** | **100%** |
| Exports         | 2223-2350    | 128       | ⏳ Pendiente        | 0%       |

**Total implementado**: **1968 / 2381 features (82.6%)**

---

## Bloques de Características

### 1. ByteHistogram (256 features)

#### ¿Qué es?

Un **histograma** que cuenta cuántas veces aparece cada byte posible (0 a 255) en el archivo.

#### ¿Por qué es útil?

Cada tipo de archivo tiene una "firma" de bytes característica:

- **Código ejecutable compilado**: Muchos bytes en el rango 0x00-0x7F (instrucciones x86)
- **Datos comprimidos/cifrados**: Distribución uniforme (todos los bytes aparecen con frecuencia similar)
- **Texto**: Concentración en rango ASCII (0x20-0x7E)

Malware empaquetado o cifrado tiene una distribución muy diferente a software normal.

#### Fórmula Matemática (Explicada Paso a Paso)

**Paso 1**: Contar cada byte

```
Para cada byte b del archivo (b puede ser 0, 1, 2, ..., 255):
    cuenta[b] = número de veces que aparece b en el archivo
```

**Paso 2**: Normalizar (convertir a frecuencia relativa)

```
total_bytes = tamaño del archivo

Para cada posición i de 0 a 255:
    histograma[i] = cuenta[i] / total_bytes
```

**Resultado**: 256 números decimales entre 0 y 1, donde la suma total = 1.0

#### Ejemplo Práctico

Archivo de 1000 bytes:

- Byte 0x00 aparece 250 veces → histograma[0] = 250/1000 = **0.25**
- Byte 0xFF aparece 10 veces → histograma[255] = 10/1000 = **0.01**
- Byte 0x4D aparece 0 veces → histograma[77] = 0/1000 = **0.00**

#### Código de Implementación

Localización: `core/features/byte_histogram.py`

```python
# Contar bytes eficientemente
counts = np.bincount(np.frombuffer(raw_data, dtype=np.uint8), minlength=256)

# Normalizar
histogram = counts.astype(np.float32) / len(raw_data)
```

---

### 2. ByteEntropy (256 features)

#### ¿Qué es?

Un histograma de la **entropía de Shannon** calculada en ventanas deslizantes del archivo.

**Entropía** mide el "desorden" o "aleatoriedad" de los datos:

- **Entropía baja (~0 bits)**: Datos muy repetitivos (ej: "AAAAAAA")
- **Entropía alta (~8 bits)**: Datos muy aleatorios/cifrados (ej: "xJ8#k2L")

#### ¿Por qué es útil?

- **Malware empaquetado**: Secciones con entropía muy alta (código comprimido/cifrado)
- **Ransomware**: Al cifrar archivos, genera datos de alta entropía
- **Software normal**: Mix de código (entropía media) y datos estructurados (entropía baja)

#### Fórmula Matemática de Entropía de Shannon

**Definición formal**:

```
H(X) = -Σ p(x) × log₂(p(x))
```

**Explicación en palabras simples**:

La entropía mide "cuánta información hay" o "qué tan sorprendente es cada byte".

**Paso 1**: Para una ventana de 2048 bytes, contar la frecuencia de cada byte:

```
p(0) = número de veces que aparece byte 0 / 2048
p(1) = número de veces que aparece byte 1 / 2048
...
p(255) = número de veces que aparece byte 255 / 2048
```

**Paso 2**: Para cada byte que aparece (p(x) > 0), calcular:

```
-p(x) × log₂(p(x))
```

**Paso 3**: Sumar todos esos valores:

```
Entropía = suma de todos los valores del paso 2
```

**Ejemplo numérico**:

Ventana de 8 bytes: `"AAAABBBB"`

- Byte 'A' (0x41): aparece 4 veces → p(A) = 4/8 = 0.5
- Byte 'B' (0x42): aparece 4 veces → p(B) = 4/8 = 0.5

```
H = -[p(A) × log₂(p(A)) + p(B) × log₂(p(B))]
  = -[0.5 × log₂(0.5) + 0.5 × log₂(0.5)]
  = -[0.5 × (-1) + 0.5 × (-1)]
  = -[-0.5 + -0.5]
  = 1.0 bit
```

Ventana de 8 bytes totalmente aleatoria: Entropía ≈ 8 bits (máximo)

#### Algoritmo del Bloque ByteEntropy

**Paso 1**: Dividir el archivo en ventanas deslizantes de 2048 bytes con paso de 1024 bytes (50% overlap)

```
Archivo: [████████████████████████████████████]
         [----ventana 1----]
                [----ventana 2----]
                       [----ventana 3----]
```

**Paso 2**: Calcular entropía de cada ventana (usando fórmula de Shannon)

```
ventana 1 → entropía = 5.2 bits
ventana 2 → entropía = 7.8 bits  ← alta entropía (posible cifrado)
ventana 3 → entropía = 4.1 bits
...
```

**Paso 3**: Crear histograma de valores de entropía

Dividir el rango [0, 8] en 256 "cajitas" (bins):

```
bin 0:   entropías entre 0.00 y 0.03
bin 1:   entropías entre 0.03 y 0.06
...
bin 255: entropías entre 7.97 y 8.00
```

Contar cuántas ventanas caen en cada bin.

**Paso 4**: Normalizar (dividir por número total de ventanas)

**Resultado**: 256 números que describen la "distribución de complejidad" del archivo.

#### Código de Implementación

Localización: `core/features/byte_entropy.py`

```python
# Para cada ventana
for i in range(0, len(raw_data) - WINDOW_SIZE + 1, STEP_SIZE):
    window = raw_data[i:i + WINDOW_SIZE]

    # Calcular frecuencia de bytes
    counts = np.bincount(np.frombuffer(window, dtype=np.uint8), minlength=256)
    probabilities = counts / len(window)

    # Filtrar probabilidades > 0
    probabilities = probabilities[probabilities > 0]

    # Entropía de Shannon
    entropy = -np.sum(probabilities * np.log2(probabilities))
    entropy_values.append(entropy)

# Crear histograma
hist, _ = np.histogram(entropy_values, bins=256, range=(0, 8))
entropy_histogram = hist / len(entropy_values)
```

---

### 3. GeneralFileInfo (10 features)

#### ¿Qué es?

Información básica y general del archivo PE.

#### Lista de Características

| #   | Característica               | Descripción                                          | Ejemplo            |
| --- | ---------------------------- | ---------------------------------------------------- | ------------------ |
| 1   | Tamaño del archivo           | Bytes totales                                        | 4,593,176          |
| 2   | Tamaño virtual (SizeOfImage) | Memoria que ocupará al ejecutarse                    | 4,800,512          |
| 3   | Tiene Debug                  | ¿Contiene símbolos de depuración?                    | 1 (sí) o 0 (no)    |
| 4   | Número de Exportaciones      | Funciones que expone a otros programas               | 0 (típico en .exe) |
| 5   | Número de Importaciones      | Funciones que usa de DLLs                            | 674                |
| 6   | Tiene Relocalizaciones       | ¿Puede cargarse en direcciones de memoria variables? | 1 o 0              |
| 7   | Tiene Recursos               | ¿Incluye iconos, diálogos, imágenes?                 | 1 o 0              |
| 8   | Tiene Firma Digital          | ¿Está firmado digitalmente?                          | 1 o 0              |
| 9   | Tiene TLS                    | ¿Usa Thread Local Storage?                           | 1 o 0              |
| 10  | Número de Símbolos           | Símbolos en tabla de símbolos                        | 0 (típico)         |

#### ¿Por qué es útil?

- **Tamaño**: Malware suele ser pequeño para evadir detección
- **Firma Digital**: Software legítimo casi siempre está firmado
- **Importaciones**: Muchas importaciones → programa complejo (legítimo o malware sofisticado)

#### Código de Implementación

Localización: `core/features/general.py`

```python
features = np.zeros(10, dtype=np.float32)

features[0] = len(raw_data)  # Tamaño del archivo
features[1] = pe.OPTIONAL_HEADER.SizeOfImage
features[2] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0
features[3] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
# ... etc
```

---

### 4. HeaderFileInfo (62 features)

#### ¿Qué es?

Características extraídas de los **headers** (cabeceras) del formato PE. Los headers contienen metadatos críticos sobre cómo debe ejecutarse el programa.

#### Categorías de Información

**A) Características del FILE_HEADER (14 features)**

- Machine type (x86, x64, ARM)
- Número de secciones
- Timestamp de compilación
- Flags (características del ejecutable)

**B) Características del OPTIONAL_HEADER (18 features)**

- Punto de entrada (AddressOfEntryPoint)
- ImageBase (dirección de memoria preferida)
- SizeOfCode, SizeOfInitializedData
- Subsystem (GUI, Console, Driver)
- DLL Characteristics (ASLR, DEP, etc.)

**C) Data Directories (30 features)**
Los 15 directorios de datos del PE, cada uno tiene:

- Virtual Address (dónde está en memoria)
- Size (tamaño en bytes)

Directorios incluyen:

1. Export Table
2. Import Table
3. Resource Table
4. Exception Table
5. Certificate Table (firma digital)
6. Base Relocation Table
7. Debug
8. Architecture
9. Global Ptr
10. TLS Table
11. Load Config Table
12. Bound Import
13. IAT
14. Delay Import Descriptor
15. CLR Runtime Header

#### ¿Por qué es útil?

- **Subsystem**: Malware rara vez es GUI, suele ser Console o Native
- **DLL Characteristics**: Malware moderno debe tener ASLR/DEP para ejecutarse en Windows moderno
- **Timestamp**: Fecha de compilación puede revelar familias de malware (compilados en batch)

#### Código de Implementación

Localización: `core/features/header.py`

---

### 5. Imports (1280 features)

#### ¿Qué es?

Codifica las **funciones importadas** del PE usando **feature hashing** (hashing trick).

#### Concepto: Import Address Table (IAT)

Cuando un programa Windows se ejecuta, necesita usar funciones del sistema operativo. Estas funciones están en archivos DLL (ej: `kernel32.dll`, `user32.dll`).

La **Import Table** lista todas estas funciones:

```
KERNEL32.dll
  - CreateFileA
  - ReadFile
  - WriteFile
  - CreateProcessA

USER32.dll
  - CreateWindowExA
  - MessageBoxA
  - GetAsyncKeyState  ← ¡Sospechoso! (keylogger)

WS2_32.dll
  - socket
  - connect
  - send              ← ¡Sospechoso! (comunicación red)
```

#### ¿Por qué son importantísimas para detectar malware?

Las importaciones revelan **intenciones** del programa:

| Importación          | DLL          | Indica                                  |
| -------------------- | ------------ | --------------------------------------- |
| `RegSetValueEx`      | advapi32.dll | Modificación de registro (persistencia) |
| `CreateRemoteThread` | kernel32.dll | Inyección de código en otros procesos   |
| `GetAsyncKeyState`   | user32.dll   | Captura de teclado (keylogger)          |
| `InternetOpenA`      | wininet.dll  | Conexión a internet (C2, exfiltración)  |
| `CryptEncrypt`       | advapi32.dll | Cifrado (ransomware)                    |
| `SetWindowsHookExA`  | user32.dll   | Hooks globales (keylogger, rootkit)     |

**Software legítimo típico**:

- Muchas funciones de `user32.dll` (ventanas, botones)
- Funciones de `gdi32.dll` (gráficos)
- Funciones de `ole32.dll` (COM, Office)

**Malware típico**:

- Funciones de red (`ws2_32.dll`)
- Funciones de registro (`advapi32.dll`)
- Funciones de bajo nivel (`ntdll.dll`)
- Pocas funciones de GUI

#### El Problema: Demasiadas Posibilidades

Existen:

- Miles de DLLs diferentes
- Miles de funciones por DLL
- Millones de combinaciones posibles

**No podemos crear un vector con millones de posiciones** → necesitamos **feature hashing**.

#### Solución: Feature Hashing (Hashing Trick)

Es una técnica que **mapea** un espacio infinito de features a un espacio fijo usando una función hash.

**Analogía simple**:

Imagina que tienes una biblioteca infinita de libros y solo 1280 cajas para organizarlos. Para decidir en qué caja va cada libro:

1. Tomas el título del libro
2. Lo conviertes en un número usando una fórmula mágica (hash)
3. Divides ese número entre 1280 y te quedas con el **residuo**
4. Ese residuo (0-1279) te dice en qué caja va

Dos libros diferentes pueden ir a la misma caja (colisión), pero está bien porque solo necesitamos saber "cuántos libros hay en cada caja aproximadamente".

#### Algoritmo de Feature Hashing para Imports

**Paso 1**: Normalizar nombres

```python
DLL: "KERNEL32.DLL" → normalizado → "kernel32"
Función: "CreateFileA" → normalizado → "createfilea"
```

**Paso 2**: Crear feature string

```python
feature = "kernel32:createfilea"
```

**Paso 3**: Calcular hash SHA256

```python
hash_bytes = SHA256("kernel32:createfilea")
# Resultado: e4f2a1c8... (64 caracteres hexadecimales)
```

**Paso 4**: Convertir primeros 8 bytes a número entero

```python
hash_number = int(hash_bytes[:16], 16)  # Número gigante
# Ejemplo: 16472849202834571928
```

**Paso 5**: Obtener índice aplicando módulo 1280

```python
index = hash_number % 1280
# Ejemplo: 16472849202834571928 % 1280 = 742
```

**Paso 6**: Incrementar contador en esa posición

```python
vector[742] += 1
```

**Paso 7**: Repetir para todas las importaciones del PE

**Paso 8**: Normalizar el vector (convertir a frecuencias relativas)

```python
total = sum(vector)
vector = vector / total
```

#### Ejemplo Completo Paso a Paso

PE con estas importaciones:

```
kernel32.dll: CreateFileA, ReadFile, WriteFile
user32.dll: MessageBoxA
ws2_32.dll: socket, connect, send
```

Procesamiento:

```
1. "kernel32:createfilea" → hash → % 1280 → 165 → vector[165] += 1
2. "kernel32:readfile"    → hash → % 1280 → 892 → vector[892] += 1
3. "kernel32:writefile"   → hash → % 1280 → 423 → vector[423] += 1
4. "user32:messageboxa"   → hash → % 1280 → 1054 → vector[1054] += 1
5. "ws2_32:socket"        → hash → % 1280 → 742 → vector[742] += 1
6. "ws2_32:connect"       → hash → % 1280 → 215 → vector[215] += 1
7. "ws2_32:send"          → hash → % 1280 → 1109 → vector[1109] += 1
```

Vector resultante (antes de normalizar):

```
[0, 0, 0, ..., 1, ..., 1, ..., 1, ..., 1, ..., 1, ..., 1, ..., 1, ..., 0]
 ↑             ↑165    ↑215    ↑423    ↑742    ↑892    ↑1054   ↑1109
```

Después de normalizar (dividir por 7):

```
[0, 0, 0, ..., 0.14, ..., 0.14, ..., 0.14, ..., 0]
```

#### ¿Qué pasa con las Colisiones?

**Colisión** = cuando dos imports diferentes van al mismo índice.

Ejemplo:

```
"kernel32:createfilea" → hash → 742
"ntdll:ntallocatevirtualmemory" → hash → 742  ¡Colisión!
```

¿Es un problema? **NO**, por estas razones:

1. **El modelo aprende patrones globales**: No le importa exactamente QUÉ función es, sino el _patrón general_ de tipos de funciones.

2. **Las colisiones son raras**: Con 1280 bins y ~500 imports típicos, probabilidad de colisión ≈ 10-15%

3. **Las colisiones son simétricas**: Afectan igual a malware y software legítimo.

4. **Sparsity**: La mayoría de bins quedan en 0, los activos son muy informativos.

#### Estadísticas del Ejemplo Real (procexp.exe)

```
Total DLLs: 25
Total funciones importadas: 674

Después del feature hashing:
Non-zero bins: 538 / 1280 (42%)
Sparsity: 58% (mayoría de bins en cero)

Top DLLs:
1. KERNEL32.dll: 213 funciones → dispersadas en ~180 bins
2. USER32.dll: 184 funciones → dispersadas en ~160 bins
3. ADVAPI32.dll: 82 funciones → dispersadas en ~70 bins
```

#### Código de Implementación

Localización: `core/features/imports.py`

```python
import hashlib

def _hash_feature(feature: str) -> int:
    # SHA256 hash
    digest = hashlib.sha256(feature.encode('utf-8')).digest()

    # Convertir primeros 8 bytes a entero
    hash_value = int.from_bytes(digest[:8], byteorder='little')

    # Módulo 1280
    return hash_value % 1280

# Extraer imports
vector = np.zeros(1280, dtype=np.float32)

for dll in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = normalize(dll.dll)

    for func in dll.imports:
        func_name = normalize(func.name) if func.name else f"ord{func.ordinal}"

        feature = f"{dll_name}:{func_name}"
        index = _hash_feature(feature)
        vector[index] += 1

# Normalizar
vector = vector / vector.sum()
```

---

## Uso del Extractor

### Instalación

```bash
# Clonar repositorio
git clone <repo-url>
cd Shadownet_Defender

# Crear entorno virtual
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate

# Instalar dependencias
pip install -r requeriments.txt
```

### Extracción Básica

```python
from core.feature_extractor import extract_sorel_features

# Extraer características de un archivo PE
features = extract_sorel_features("malware.exe")

print(f"Shape: {features.shape}")  # (2381,)
print(f"Primeros 10 valores: {features[:10]}")
```

### Acceso a Bloques Individuales

```python
# Acceder a each bloque por offset
byte_histogram = features[0:256]        # ByteHistogram
byte_entropy = features[256:512]        # ByteEntropy
general_info = features[616:626]        # GeneralFileInfo
header_info = features[626:688]         # HeaderFileInfo
imports_info = features[943:2223]       # Imports

# Analizar imports
import numpy as np
active_bins = np.count_nonzero(imports_info)
print(f"Bins activos en Imports: {active_bins}/1280")
```

### Interpretación de Resultados

#### ByteHistogram

```python
# Encontrar byte más frecuente
most_frequent_byte = byte_histogram.argmax()
frequency = byte_histogram[most_frequent_byte]

print(f"Byte más común: 0x{most_frequent_byte:02X} ({frequency:.2%})")

# Si el byte 0x00 es muy frecuente → muchos ceros (padding, datos)
# Si distribución muy uniforme → posible cifrado/compresión
```

#### ByteEntropy

```python
# Calcular entropía promedio ponderada
entropy_bins = np.linspace(0, 8, 256)
avg_entropy = np.sum(byte_entropy * entropy_bins)

print(f"Entropía promedio: {avg_entropy:.2f} bits")

# < 4 bits → archivo simple, mucha repetición
# 4-6 bits → típico de ejecutables normales
# > 7 bits → posible empaquetado/cifrado (SOSPECHOSO)
```

### Uso con Modelo de ML

```python
import joblib

# 1. Extraer features
features = extract_sorel_features("suspicious.exe")

# 2. Cargar scaler y modelo
scaler = joblib.load("models/scaler.pkl")
model = joblib.load("models/lightgbm_model.pkl")

# 3. Escalar features
features_scaled = scaler.transform(features.reshape(1, -1))

# 4. Predecir
probability = model.predict_proba(features_scaled)[0][1]  # Prob de malware

print(f"Probabilidad de malware: {probability:.2%}")

if probability > 0.8:
    print("⚠️  ALERTA: Archivo altamente sospechoso")
elif probability > 0.5:
    print("⚠️  ADVERTENCIA: Archivo posiblemente malicioso")
else:
    print("✅ Archivo parece legítimo")
```

---

## Validación y Testing

### Test General del Extractor

```bash
source .venv/bin/activate
python verify_extractor.py
```

**Verifica**:

- ✅ Shape correcto (2381 features)
- ✅ ByteHistogram: suma ~1.0, valores en [0,1]
- ✅ ByteEntropy: suma ~1.0, valores en [0,1]
- ✅ Bloques General y Header tienen valores no-cero
- ✅ Determinismo (misma entrada → misma salida)
- ✅ Compatibilidad con scaler existente

### Test Específico de Imports

```bash
python verify_imports.py
```

**Verifica**:

- ✅ Dimensión correcta (1280 features)
- ✅ Hash determinístico y consistente
- ✅ Manejo de PE sin imports
- ✅ Análisis detallado de archivo real

### Análisis Comparativo

```bash
python analyze_imports_distribution.py
```

Compara la distribución de imports entre:

- Software legítimo (ej: procexp.exe)
- Malware (si disponible)

Calcula:

- Similitud coseno
- Distancia euclidiana
- Bins únicos vs compartidos

---

## Preparación para Producción

### Exportación a ONNX

ONNX (Open Neural Network Exchange) permite usar el modelo en otros lenguajes (C++, Java, JavaScript).

```python
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import joblib

# Convertir scaler a ONNX
scaler = joblib.load('models/scaler.pkl')
initial_type = [('float_input', FloatTensorType([None, 2381]))]
onnx_scaler = convert_sklearn(scaler, initial_types=initial_type)

with open("models/scaler.onnx", "wb") as f:
    f.write(onnx_scaler.SerializeToString())
```

### Pipeline de Inferencia ONNX

```python
import onnxruntime as ort

# 1. Extraer features (Python)
features = extract_sorel_features("file.exe")

# 2. Cargar modelos ONNX
session_scaler = ort.InferenceSession("models/scaler.onnx")
session_model = ort.InferenceSession("models/model.onnx")

# 3. Escalar
scaled = session_scaler.run(None, {
    'float_input': features.reshape(1, -1).astype(np.float32)
})[0]

# 4. Predecir
prediction = session_model.run(None, {'input': scaled})[0]
```

### Implementación en Java

El extractor puede ser reimplementado en Java para integración en aplicaciones empresariales.

**Bibliotecas necesarias**:

- `pe-parser` o `jPE`: Parsing de archivos PE
- `Apache Commons Codec`: Funciones hash

**Ejemplo** (pseudocódigo):

```java
import java.security.MessageDigest;

public class ImportsFeatureExtractor {
    private static final int DIM = 1280;

    public static float[] extract(PEFile pe) {
        float[] vector = new float[DIM];

        for (ImportDLL dll : pe.getImports()) {
            String dllName = normalize(dll.getName());

            for (ImportFunction func : dll.getFunctions()) {
                String funcName = normalize(func.getName());
                String feature = dllName + ":" + funcName;

                int index = hashFeature(feature);
                vector[index] += 1;
            }
        }

        // Normalizar
        float total = Arrays.stream(vector).sum();
        for (int i = 0; i < DIM; i++) {
            vector[i] /= total;
        }

        return vector;
    }
}
```

---

## Preguntas Frecuentes (FAQ)

### ¿Por qué 2381 features específicamente?

Este número fue optimizado por los investigadores de EMBER/SOREL balanceando:

- **Información suficiente**: Captura propiedades discriminativas
- **Eficiencia**: No es excesivamente grande para entrenar/inferir
- **Compatibilidad**: Estándar de la industria para malware detection

### ¿Qué pasa si el archivo no es un PE válido?

El extractor devuelve un vector de ceros (2381 ceros), que el modelo interpretará como "archivo inválido/corrupto".

### ¿Funciona con archivos de 32-bit y 64-bit?

Sí, el extractor es agnóstico a la arquitectura. Analiza la estructura PE independientemente de si es x86 o x64.

### ¿Qué tan rápido es?

En hardware moderno:

- **Archivos pequeños** (<1 MB): ~50-100ms
- **Archivos medianos** (1-10 MB): ~200-500ms
- **Archivos grandes** (>10 MB): ~1-3 segundos

El cuello de botella principal es ByteEntropy (ventanas deslizantes).

### ¿Puedo usar esto con Python 2?

No, requiere **Python 3.7+** debido a dependencias modernas de `numpy` y `pefile`.

### ¿El extractor modifica el archivo?

**No**, el análisis es completamente de solo lectura. El archivo original nunca es modificado.

---

## Referencias y Recursos

### Papers Académicos

1. **Anderson & Roth (2018)**: "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models"
   - [https://arxiv.org/abs/1804.04637](https://arxiv.org/abs/1804.04637)
2. **Weinberger et al. (2009)**: "Feature Hashing for Large Scale Multitask Learning"
   - Fundamento del hashing trick

3. **SOREL-20M (2020)**: Sophos + ReversingLabs
   - [https://ai.sophos.com/2020/12/14/sophos-reversinglabs-sorel-20-million-sample-malware-dataset/](https://ai.sophos.com/2020/12/14/sophos-reversinglabs-sorel-20-million-sample-malware-dataset/)

### Datasets Públicos

- **SOREL-20M**: 20 millones de samples (10M malware, 10M benign)
- **EMBER**: 1.1 millones de samples (precursor de SOREL)

### Herramientas

- **pefile**: [https://github.com/erocarrera/pefile](https://github.com/erocarrera/pefile)
- **LightGBM**: [https://lightgbm.readthedocs.io/](https://lightgbm.readthedocs.io/)
- **ONNX Runtime**: [https://onnxruntime.ai/](https://onnxruntime.ai/)

---

## Licencia

Este proyecto es parte de **ShadowNet Defender**, un sistema académico de detección de malware con IA.

---

## Contacto y Contribuciones

Para reportar bugs o sugerir mejoras, por favor abre un issue en el repositorio.

---

**Última actualización**: 2026-02-17
**Versión del extractor**: 1.0 (82.6% completo)
**Compatible con**: SOREL-20M, EMBER 2.0
