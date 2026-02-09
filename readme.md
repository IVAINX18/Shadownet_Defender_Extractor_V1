# Módulo de Extracción de Características SOREL/EMBER

Este módulo implementa un extractor de características modular para archivos PE de Windows, compatible con los modelos entrenados en los datasets SOREL-20M o EMBER 2.0.

## Objetivo
Generar un vector de características NumPy de tamaño **2381** que pueda ser consumido por el modelo de detección de malware.

## Estructura

El extractor está diseñado por bloques (`FeatureBlock`). Actualmente se encuentran implementados:

1.  **GeneralFileInfo** (10 características): Información general del archivo.
2.  **HeaderFileInfo** (62 características): Información del encabezado PE.

Los demás bloques (ByteHistogram, Imports, etc.) están definidos en el mapa de memoria pero se rellenan con ceros hasta su implementación futura.

## Uso

### Extracción Básica

```python
from core.features.extractor import PEFeatureExtractor

# Inicializar extractor
extractor = PEFeatureExtractor()

# Extraer características de una ruta de archivo
try:
    vector = extractor.extract("ruta/al/malware.exe")
    print(f"Vector generado con forma: {vector.shape}") # (2381,)
except Exception as e:
    print(f"Error: {e}")
```

### Extensión (Cómo añadir más características)

Para implementar un nuevo bloque (ej. Strings):

1.  Crear un nuevo archivo en `core/features/strings.py`.
2.  Heredar de `FeatureBlock`.
3.  Implementar `extract(self, pe, raw_data)`.
4.  Registrar el bloque en `core/features/extractor.py` y actualizar los offsets.

## Validación

Puede validar el correcto funcionamiento ejecutando:

```bash
python verify_extractor.py
```
