# Módulo de Extracción de Características SOREL/EMBER

Este módulo implementa un extractor de características modular para archivos PE de Windows, compatible con los modelos entrenados en los datasets SOREL-20M

## Objetivo

Generar un vector de características NumPy de tamaño **2381** que pueda ser consumido por el modelo de detección de malware.

## Estructura

El extractor está diseñado por bloques (`FeatureBlock`). Actualmente se encuentran implementados:

### Bloques Implementados (688 / 2381 features = 28.9%)

| Bloque              | Offset  | Dimensión | Descripción                                                                                                                       |
| ------------------- | ------- | --------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **ByteHistogram**   | 0-255   | 256       | Histograma normalizado de bytes [0x00-0xFF]. Captura la distribución de frecuencia de bytes en el archivo.                        |
| **ByteEntropy**     | 256-511 | 256       | Histograma de entropía de Shannon calculada mediante ventanas deslizantes de 2048 bytes. Detecta secciones cifradas/empaquetadas. |
| **GeneralFileInfo** | 616-625 | 10        | Información general del archivo (tamaño, exportaciones, importaciones, flags).                                                    |
| **HeaderFileInfo**  | 626-687 | 62        | Información del encabezado PE (características, subsistema, directorios de datos).                                                |

### Bloques Pendientes

Los siguientes bloques están definidos en el mapa de memoria pero se rellenan con ceros hasta su implementación:

- **StringExtractor** (512-615): 104 características de strings
- **SectionInfo** (688-942): 255 características de secciones
- **Imports** (943-2222): 1280 características de importaciones
- **Exports** (2223-2350): 128 características de exportaciones

## Uso

### Extracción Básica

```python
from core.feature_extractor import extract_sorel_features

# Extraer características de una ruta de archivo
vector = extract_sorel_features("ruta/al/malware.exe")
print(f"Vector generado con forma: {vector.shape}") # (2381,)

# Acceder a bloques individuales
byte_histogram = vector[0:256]      # ByteHistogram
byte_entropy = vector[256:512]      # ByteEntropy
general_info = vector[616:626]      # GeneralFileInfo
header_info = vector[626:688]       # HeaderFileInfo
```

### Interpretación de Características

#### ByteHistogram (0-255)

Distribución de frecuencia normalizada de bytes. Útil para:

- Detectar código compilado vs datos empaquetados
- Identificar patrones de compresión/cifrado
- Análisis de composición del ejecutable

```python
# Encontrar el byte más frecuente
most_frequent = byte_histogram.argmax()
print(f"Byte más frecuente: 0x{most_frequent:02X} ({byte_histogram[most_frequent]:.2%})")
```

#### ByteEntropy (256-511)

Histograma de entropía de Shannon (ventanas de 2048 bytes). Útil para:

- Detectar secciones cifradas (alta entropía ~8 bits)
- Identificar código ejecutable (entropía media)
- Localizar datos estructurados (entropía baja)

```python
import numpy as np

# Calcular entropía promedio ponderada
entropy_bins = np.linspace(0, 8, 256)
avg_entropy = np.sum(byte_entropy * entropy_bins)
print(f"Entropía promedio: {avg_entropy:.2f} bits")
```

### Extensión (Cómo añadir más características)

Para implementar un nuevo bloque (ej. Strings):

1.  Crear un nuevo archivo en `core/features/strings.py`.
2.  Heredar de `FeatureBlock`.
3.  Implementar `extract(self, pe, raw_data)`.
4.  Registrar el bloque en `core/features/extractor.py` y actualizar los offsets.

## Validación

El script de validación verifica:

- ✅ Shape correcta del vector (2381,)
- ✅ ByteHistogram: suma ~1.0, valores en [0,1]
- ✅ ByteEntropy: suma ~1.0, valores en [0,1]
- ✅ Bloques General y Header contienen valores no-cero
- ✅ Determinismo (extracciones idénticas)
- ✅ Compatibilidad con scaler existente

```bash
# Activar entorno virtual y ejecutar validación
source .venv/bin/activate
python verify_extractor.py
```

## Características Técnicas

- **Determinismo garantizado**: Mismo archivo → mismo vector de features
- **Eficiencia**: Operaciones vectorizadas con NumPy
- **Robustez**: Manejo de edge cases (archivos vacíos, pequeños, etc.)
- **Compatibilidad**: 100% compatible con modelos SOREL/EMBER pre-entrenados
