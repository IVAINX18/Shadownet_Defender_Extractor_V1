"""
Bloque de Características de Sección (SectionInfo)

Implementa la extracción de metadatos, estadísticas y entropía de las secciones del PE.
Sigue una arquitectura en capas para garantizar robustez y mantenibilidad.

MAPA DE CARACTERÍSTICAS (Total: 255):
- Estadísticas Globales (10): promedios, totales, entropía global
- Flags & Permisos (5): conteos de RWX, Executable, etc.
- Distribución Entropía (50): histograma de entropía de secciones
- Distribución Tamaño Raw (50): histograma logarítmico de tamaños raw
- Distribución Tamaño Virtual (50): histograma logarítmico de tamaños virtuales
- Nombres Hashed (90): feature hashing de nombres de secciones

AUTOR: ShadowNet Defender Team
"""

from .base import FeatureBlock
import pefile
import numpy as np
import math
import hashlib

class SectionInfoBlock(FeatureBlock):
    """
    Extrae características detalladas de las secciones del archivo PE.
    """
    
    # Dimensión total fija
    DIM = 255
    
    # Configuración de Histogramas
    ENTROPY_BINS = 50
    SIZE_BINS = 50
    NAME_HASH_BINS = 90
    
    @property
    def name(self) -> str:
        return "SectionInfoBlock"
    
    @property
    def dim(self) -> int:
        return self.DIM
        
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calcula entropía de Shannon de un bloque de datos.
        H(X) = -Σ p(x) * log2(p(x))
        """
        if not data:
            return 0.0
            
        # Frecuencia de bytes (0-255)
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        
        # Probabilidades
        probs = counts / len(data)
        
        # Filtrar probs > 0
        probs = probs[probs > 0]
        
        # Shannon entropy
        entropy = -np.sum(probs * np.log2(probs))
        
        return float(entropy)

    def _hash_name(self, name: str) -> int:
        """
        Hash determinístico para nombres de sección.
        Mapea a un índice [0, NAME_HASH_BINS-1].
        """
        if not name:
            return 0
            
        # Normalizar: lowercase, strip, eliminar nulos
        normalized = name.strip().lower().replace('\x00', '')
        
        # SHA256
        digest = hashlib.sha256(normalized.encode('utf-8', errors='replace')).digest()
        val = int.from_bytes(digest[:8], 'little')
        
        return val % self.NAME_HASH_BINS

    def extract(self, pe: pefile.PE, raw_data: bytes = None) -> np.ndarray:
        """
        Extrae el vector de 255 características de las secciones.
        """
        vector = np.zeros(self.DIM, dtype=np.float32)
        
        # 1. Capa de Extracción & Cálculo de Métricas (Raw -> Metrics)
        sections = pe.sections
        num_sections = len(sections)
        
        # Listas para almacenar métricas por sección
        raw_sizes = []
        virt_sizes = []
        entropies = []
        
        # Contadores de Flags
        count_exec = 0
        count_write = 0
        count_read = 0
        count_rwx = 0
        count_shared = 0
        
        # Histogramas acumuladores
        hist_entropy = np.zeros(self.ENTROPY_BINS, dtype=np.float32)
        hist_raw_size = np.zeros(self.SIZE_BINS, dtype=np.float32)
        hist_virt_size = np.zeros(self.SIZE_BINS, dtype=np.float32)
        hist_names = np.zeros(self.NAME_HASH_BINS, dtype=np.float32)
        
        if num_sections > 0:
            for section in sections:
                # Tamaños
                r_size = section.SizeOfRawData
                v_size = section.Misc_VirtualSize
                
                raw_sizes.append(r_size)
                virt_sizes.append(v_size)
                
                # Entropía (usar get_data() de pefile para robustez)
                try:
                    sect_data = section.get_data()
                    entropy = self._calculate_entropy(sect_data)
                except Exception:
                    entropy = 0.0
                entropies.append(entropy)
                
                # Flags (Características)
                props = getattr(section, 'Characteristics', 0)
                is_exec = (props & 0x20000000) > 0  # IMAGE_SCN_MEM_EXECUTE
                is_read = (props & 0x40000000) > 0  # IMAGE_SCN_MEM_READ
                is_write = (props & 0x80000000) > 0 # IMAGE_SCN_MEM_WRITE
                is_shared = (props & 0x10000000) > 0 # IMAGE_SCN_MEM_SHARED
                
                if is_exec: count_exec += 1
                if is_read: count_read += 1
                if is_write: count_write += 1
                if is_shared: count_shared += 1
                if is_read and is_write and is_exec: count_rwx += 1
                
                # Nombres (Hashing)
                try:
                    name = section.Name.decode('utf-8', errors='replace')
                except:
                    name = ""
                name_idx = self._hash_name(name)
                hist_names[name_idx] += 1
                
                # Histogramas (Binning)
                # Entropía [0, 8]
                e_bin = int((entropy / 8.0) * (self.ENTROPY_BINS - 1))
                e_bin = max(0, min(e_bin, self.ENTROPY_BINS - 1))
                hist_entropy[e_bin] += 1
                
                # Tamaño Raw (Logarítmico)
                # log2(size + 1). Max esperado ~ 50MB -> log2(50*1024*1024) ~= 25.5
                # Vamos a mapear [0, 26] a [0, 49]
                if r_size > 0:
                    log_r = math.log2(r_size + 1)
                    r_bin = int((log_r / 26.0) * (self.SIZE_BINS - 1))
                    r_bin = max(0, min(r_bin, self.SIZE_BINS - 1))
                    hist_raw_size[r_bin] += 1
                else:
                    hist_raw_size[0] += 1 # Tamaño 0
                    
                # Tamaño Virtual (Logarítmico)
                if v_size > 0:
                    log_v = math.log2(v_size + 1)
                    v_bin = int((log_v / 26.0) * (self.SIZE_BINS - 1))
                    v_bin = max(0, min(v_bin, self.SIZE_BINS - 1))
                    hist_virt_size[v_bin] += 1
                else:
                    hist_virt_size[0] += 1 # Tamaño 0

        # 2. Capa de Vectorización (Metrics -> Vector)
        
        # Grupo A: Estadísticas Globales (índices 0-9)
        vector[0] = num_sections
        vector[1] = sum(1 for s in raw_sizes if s == 0) # Secciones vacías
        vector[2] = np.mean(raw_sizes) if raw_sizes else 0
        vector[3] = np.mean(virt_sizes) if virt_sizes else 0
        vector[4] = np.average(entropies, weights=raw_sizes) if raw_sizes and sum(raw_sizes) > 0 else 0 # Weighted Entropy
        vector[5] = min(entropies) if entropies else 0
        vector[6] = max(entropies) if entropies else 0
        
        # Ratio Raw/Virtual promedio (detección de empaquetado)
        ratios = []
        for r, v in zip(raw_sizes, virt_sizes):
            if v > 0: ratios.append(r / v)
            else: ratios.append(0)
        vector[7] = np.mean(ratios) if ratios else 0
        
        vector[8] = sum(raw_sizes)
        vector[9] = sum(virt_sizes)
        
        # Grupo B: Flags & Permisos (índices 10-14)
        vector[10] = count_exec
        vector[11] = count_write
        vector[12] = count_read
        vector[13] = count_rwx
        vector[14] = count_shared
        
        # Grupo C: Distribuciones (Normalizadas)
        
        # Entropía (15-64)
        if num_sections > 0: hist_entropy /= num_sections
        vector[15 : 15 + self.ENTROPY_BINS] = hist_entropy
        
        # Tamaño Raw (65-114)
        if num_sections > 0: hist_raw_size /= num_sections
        vector[65 : 65 + self.SIZE_BINS] = hist_raw_size
        
        # Tamaño Virtual (115-164)
        if num_sections > 0: hist_virt_size /= num_sections
        vector[115 : 115 + self.SIZE_BINS] = hist_virt_size
        
        # Grupo D: Nombres Hashed (165-254)
        # Normalizar por número de secciones también
        if num_sections > 0: hist_names /= num_sections
        vector[165 : 165 + self.NAME_HASH_BINS] = hist_names
        
        # Validación final de dimensión
        assert len(vector) == self.DIM, f"Error dimensión vector: {len(vector)} != {self.DIM}"
        
        return vector
