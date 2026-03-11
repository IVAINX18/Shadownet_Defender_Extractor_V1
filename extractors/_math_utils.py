"""
Utilidades matemáticas compartidas para los bloques de extracción de features.

Este módulo centraliza funciones que antes estaban duplicadas en múltiples
extractores (byte_entropy, section_info, string_extractor, imports, exports).

PARA JUNIORS:
    La regla DRY (Don't Repeat Yourself) es fundamental en ingeniería de software.
    Si una función aparece copiada en 3 archivos distintos, cualquier bug debe
    corregirse en los 3 lugares. Al centralizarla aquí, el bug se corrige UNA vez.
"""

import hashlib

import numpy as np


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calcula la entropía de Shannon de un bloque de bytes.

    La entropía mide el nivel de "desorden" o aleatoriedad de la información.

    Fórmula:
        H(X) = -Σ p(x) * log₂(p(x))

    Rangos de referencia (para bytes, máximo teórico = 8 bits):
        - H ≈ 0.0  → Datos completamente uniformes (ej: archivo de solo ceros)
        - H ≈ 4.0  → Código compilado normal (.text section)
        - H ≈ 7.2+ → Datos comprimidos o cifrados (alerta de packing/cifrado)
        - H ≈ 8.0  → Máxima aleatoriedad (distribución uniforme perfecta)

    Args:
        data: Bloque de bytes a analizar.

    Returns:
        Entropía en bits, rango [0.0, 8.0].
    """
    if not data:
        return 0.0

    # Contar frecuencia de cada valor de byte (0-255)
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)

    # Calcular probabilidades (frecuencia relativa)
    probabilities = counts / len(data)

    # Filtrar probabilidades cero para evitar log(0) = -inf
    probabilities = probabilities[probabilities > 0]

    # Entropía de Shannon: -Σ p(x) * log₂(p(x))
    entropy = -np.sum(probabilities * np.log2(probabilities))

    return float(entropy)


def hash_feature_sha256(feature: str, dim: int) -> int:
    """
    Calcula un índice determinista en [0, dim-1] usando SHA256.

    PARA JUNIORS:
        Esto implementa el "Feature Hashing" o "Hashing Trick".
        En vez de mantener un diccionario de miles de nombres de funciones
        (ej: "kernel32.dll:WriteFile"), usamos un hash criptográfico para
        proyectar cada nombre a un índice fijo en un vector de tamaño `dim`.

        Ventajas:
        - Tamaño fijo sin importar cuántas funciones existan
        - Determinista: el mismo string siempre produce el mismo índice
        - Cross-platform: funciona igual en cualquier OS/arquitectura

        Desventaja:
        - Posibles colisiones (dos strings distintos → mismo índice),
          pero en la práctica es estadísticamente tolerable.

    Args:
        feature: String a hashear (ej: "kernel32:writefile").
        dim: Dimensión del vector destino (ej: 1280 para imports, 128 para exports).

    Returns:
        Índice en rango [0, dim - 1].
    """
    # Calcular SHA256 del string codificado en UTF-8
    digest = hashlib.sha256(feature.encode("utf-8", errors="replace")).digest()

    # Tomar los primeros 8 bytes y convertir a entero (little-endian)
    hash_value = int.from_bytes(digest[:8], byteorder="little")

    # Proyectar al rango [0, dim-1] con módulo
    return hash_value % dim
