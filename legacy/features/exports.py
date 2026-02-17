"""
Bloque de Características de Exportaciones (ExportsFeatureBlock)

Codifica las funciones exportadas por el PE utilizando Feature Hashing.
Esto permite mapear un número arbitrario de nombres de exportación a un vector fijo.

MAPA DE CARACTERÍSTICAS (Total: 128):
- Índices 0-127: Histogramas de hashes de nombres de funciones exportadas (normalizados).

TÉCNICA:
Feature Hashing (Hashing Trick)
Formula: index = SHA256(export_name) % 128
"""

from .base import FeatureBlock
import pefile
import numpy as np
import hashlib

class ExportsFeatureBlock(FeatureBlock):
    """
    Extrae características de la tabla de exportaciones (Export Directory).
    Utiliza Feature Hashing para codificar los nombres de las funciones exportadas.
    """
    
    # Dimensión fija de 128 features
    DIM = 128
    
    @property
    def name(self) -> str:
        return "ExportsFeatureBlock"
    
    @property
    def dim(self) -> int:
        return self.DIM

    def _hash_feature(self, feature: str) -> int:
        """
        Aplica hashing determinístico usando SHA256.
        Retorna un índice en el rango [0, 127].
        """
        # SHA256 es robusto y estándar
        digest = hashlib.sha256(feature.encode('utf-8', errors='replace')).digest()
        
        # Convertimos los primeros 8 bytes a un entero
        # Esto nos da suficiente entropía para el módulo
        val = int.from_bytes(digest[:8], 'little')
        
        # Módulo 128 para mapear al vector
        return val % self.DIM

    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        """
        Extrae el vector de 128 features de exportaciones.
        """
        vector = np.zeros(self.DIM, dtype=np.float32)
        
        # 1. Capa de Parsing
        # Verificamos si existe el directorio de exportaciones
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return vector

        try:
            # 2. Capa de Normalización y Procesamiento
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    # Si tiene nombre: decodificar y limpiar
                    try:
                        func_name = exp.name.decode('utf-8', errors='ignore').strip().lower()
                    except:
                        func_name = f"ord{exp.ordinal}" # Fallback
                else:
                    # Si es export por ordinal (sin nombre)
                    func_name = f"ord{exp.ordinal}"
                
                # 3. Capa de Hashing
                # Calculamos el índice para este string
                idx = self._hash_feature(func_name)
                
                # 4. Capa de Vectorización
                # Incrementamos el contador en ese bin (feature hashing)
                vector[idx] += 1
                
        except AttributeError:
            # Manejo robusto de PEs malformados
            pass
            
        # Normalización L1 (Frecuencia relativa)
        # Dividimos por la suma total para que el vector sume 1.0 (o 0 si vacío)
        total = np.sum(vector)
        if total > 0:
            vector = vector / total
            
        assert len(vector) == self.DIM
        return vector
