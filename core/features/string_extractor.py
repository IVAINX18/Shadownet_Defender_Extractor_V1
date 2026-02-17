"""
Bloque de Características de String (StringExtractor)

Extrae información estadística y patrones de strings ASCII y Unicode.
Analiza Indicadores de Compromiso (IoC) como URLs, IPs, Rutas, etc.

MAPA DE CARACTERÍSTICAS (Total: 104):
- Estadísticas Globales (5): Num strings, longitudes, entropía
- Patrones IoC (10): URLs, IPs, Paths, Registry, Emails, etc.
- Histograma Longitud (40): Distribución logarítmica de longitudes
- Histograma Entropía (40): Distribución de entropía de strings
- Caracteres Especiales (9): Ratios de dígitos, letras, símbolos

AUTOR: ShadowNet Defender Team
"""

from .base import FeatureBlock
import pefile
import numpy as np
import re
import math

class StringExtractorBlock(FeatureBlock):
    """
    Extrae características basadas en strings del archivo PE.
    Detecta patrones sospechosos y analiza distribuciones.
    """
    
    # Dimensión total fija
    DIM = 104
    
    # Regex Patterns (Bytes para velocidad)
    # ASCII Strings: 4+ chars imprimibles
    REGEX_ASCII = re.compile(rb'[\x20-\x7E]{4,}')
    
    # Patrones específicos (IoC)
    REGEX_URL = re.compile(rb'https?://[\w\-\.]+')
    REGEX_PATH = re.compile(rb'[C-Z]:\\[\w\\]+|/usr/bin/|/bin/|/tmp/')
    REGEX_IP = re.compile(rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    REGEX_REGISTRY = re.compile(rb'HKEY_[\w]+|HKLM|HKCU')
    REGEX_EMAIL = re.compile(rb'[\w\.-]+@[\w\.-]+\.\w+')
    REGEX_MZ = re.compile(rb'MZ') # PE header embedido
    REGEX_POWERSHELL = re.compile(rb'powershell|cmd\.exe|bitsadmin', re.IGNORECASE)
    REGEX_CRYPTO = re.compile(rb'bitcoin|wallet|monero|crypto', re.IGNORECASE)
    REGEX_API = re.compile(rb'LoadLibrary|GetProcAddress|VirtualAlloc|CreateRemoteThread', re.IGNORECASE)
    REGEX_FMT = re.compile(rb'%[sdxf]')
    
    # Configuración Histogramas
    LEN_BINS = 40
    ENT_BINS = 40
    
    @property
    def name(self) -> str:
        return "StringExtractorBlock"
    
    @property
    def dim(self) -> int:
        return self.DIM

    def _calculate_entropy(self, data: bytes) -> float:
        """Calcula entropía de Shannon de un string."""
        if not data: return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts[counts > 0] / len(data)
        return -np.sum(probs * np.log2(probs))

    def extract(self, pe: pefile.PE, raw_data: bytes) -> np.ndarray:
        """
        Extrae el vector de 104 características de strings.
        """
        vector = np.zeros(self.DIM, dtype=np.float32)
        
        # 1. Capa de Extracción (Harvesting)
        # Extraemos strings ASCII del raw_data completo
        # (Podríamos añadir Unicode decoding, pero ASCII byte-search es muy eficiente y cubre la mayoría de IoCs)
        all_strings = self.REGEX_ASCII.findall(raw_data)
        
        num_strings = len(all_strings)
        if num_strings == 0:
            return vector
            
        # 2. Capa de Filtrado y Métricas (Analysis)
        lengths = []
        entropies = []
        total_chars = 0
        
        # Contadores IoC
        count_url = 0
        count_path = 0
        count_ip = 0
        count_reg = 0
        count_email = 0
        count_mz = 0
        count_ps = 0
        count_crypto = 0
        count_api = 0
        count_fmt = 0
        
        # Contadores de Caracteres
        c_digits = 0
        c_upper = 0
        c_lower = 0
        c_space = 0
        c_special = 0
        
        for s in all_strings:
            slen = len(s)
            lengths.append(slen)
            total_chars += slen
            
            # Entropía
            ent = self._calculate_entropy(s)
            entropies.append(ent)
            
            # Chequeo de Patrones (IoC)
            # Solo chequeamos si tiene longitud razonable para evitar falsos positivos en strings cortos
            if slen > 4:
                if self.REGEX_URL.search(s): count_url += 1
                if self.REGEX_PATH.search(s): count_path += 1
                if self.REGEX_IP.search(s): count_ip += 1
                if self.REGEX_REGISTRY.search(s): count_reg += 1
                if self.REGEX_EMAIL.search(s): count_email += 1
                if self.REGEX_POWERSHELL.search(s): count_ps += 1
                if self.REGEX_CRYPTO.search(s): count_crypto += 1
                if self.REGEX_API.search(s): count_api += 1
            
            if s.startswith(b'MZ'): count_mz += 1
            if self.REGEX_FMT.search(s): count_fmt += 1
            
            # Análisis de Caracteres (muestreo rápido con numpy)
            arr = np.frombuffer(s, dtype=np.uint8)
            c_digits += np.sum((arr >= 48) & (arr <= 57))
            c_upper += np.sum((arr >= 65) & (arr <= 90))
            c_lower += np.sum((arr >= 97) & (arr <= 122))
            c_space += np.sum(arr == 32)
            # Special es el resto
            
        c_special = total_chars - (c_digits + c_upper + c_lower + c_space)
        
        # 3. Capa de Vectorización (Feature Mapping)
        
        # Grupo A: Estadísticas Globales (0-4)
        vector[0] = np.log1p(num_strings)
        vector[1] = np.mean(lengths)
        vector[2] = np.max(lengths)
        vector[3] = np.mean(entropies)
        vector[4] = np.log1p(total_chars)
        
        # Grupo B: Patrones IoC (5-14)
        vector[5] = count_path
        vector[6] = count_url
        vector[7] = count_reg
        vector[8] = count_mz
        vector[9] = count_ip
        vector[10] = count_email
        vector[11] = count_api
        vector[12] = count_ps
        vector[13] = count_crypto
        vector[14] = count_fmt
        
        # Grupo C: Histogramas (15-94)
        
        # Longitud (15-54): Log scale bins
        # Mapping: [0, 40] bins. Log2(len). Max len ~ 1MB -> Log2 ~ 20.
        # Scale to 40 bins.
        for l in lengths:
            val = math.log2(l)
            bin_idx = int((val / 20.0) * (self.LEN_BINS - 1))
            bin_idx = max(0, min(bin_idx, self.LEN_BINS - 1))
            vector[15 + bin_idx] += 1
            
        # Normalizar histograma longitud
        if num_strings > 0:
            vector[15:55] /= num_strings
            
        # Entropía (55-94): [0, 8] bits
        for e in entropies:
            bin_idx = int((e / 8.0) * (self.ENT_BINS - 1))
            bin_idx = max(0, min(bin_idx, self.ENT_BINS - 1))
            vector[55 + bin_idx] += 1
            
        # Normalizar histograma entropía
        if num_strings > 0:
            vector[55:95] /= num_strings
            
        # Grupo D: Caracteres Especiales (95-103)
        if total_chars > 0:
            vector[95] = c_digits / total_chars
            vector[96] = c_upper / total_chars
            vector[97] = c_lower / total_chars
            vector[98] = c_space / total_chars
            vector[99] = c_special / total_chars
            vector[100] = (c_digits + c_special) / total_chars # Complexity ratio
            vector[101] = c_lower / (c_upper + c_lower + 1e-6) # Case ratio
            vector[102] = 0 # Reservado
            vector[103] = 0 # Reservado
            
        # Validación final
        assert len(vector) == self.DIM, f"Dimensión incorrecta {len(vector)}"
        
        return vector
