"""
Feature Hashing para Import Address Table (IAT)

FUNDAMENTO TEÓRICO:
El feature hashing (hashing trick) mapea un espacio de features potencialmente infinito
(todas las combinaciones posibles de DLL:función) a un espacio de dimensión fija (1280)
usando una función hash criptográfica determinística.

VENTAJAS:
1. No requiere vocabulario pre-construido (no hay fase de fit())
2. Maneja features nunca vistas (zero-shot capability)
3. Determinístico y reproducible (misma entrada → misma salida)
4. Eficiente en memoria: O(k) donde k = num_imports, no O(V) donde V = vocabulario total

TRADE-OFF (Colisiones):
Con M=1280 bins y N imports, la probabilidad de colisión es inevitable.
Sin embargo, los modelos ML (especialmente ensemble methods como LightGBM/XGBoost)
son robustos a este "ruido estructurado" porque:
- Las colisiones son simétricas (afectan igualmente malware y benignos)
- El patrón global de la distribución sigue siendo discriminativo
- La regularización L1/L2 penaliza sobreajuste

APLICACIÓN A MALWARE DETECTION:
Malware vs Software Legítimo tienen distribuciones de imports fundamentalmente diferentes:

Malware típico:
- ws2_32.dll (red/C2): socket, send, recv, connect
- advapi32.dll (registro/persistencia): RegSetValueEx, CreateServiceA
- ntdll.dll (bajo nivel): NtCreateThreadEx, NtWriteVirtualMemory (inyección)
- bcrypt.dll / advapi32 crypto APIs (ransomware)

Software Legítimo típico:
- user32.dll / gdi32.dll (GUI): CreateWindowEx, BeginPaint
- ole32.dll / oleaut32.dll (COM): CoCreateInstance
- shell32.dll: SHGetFolderPath

El modelo aprende pesos discriminativos por bin, capturando estos patrones.

REFERENCIAS:
- Weinberger et al. (2009): "Feature Hashing for Large Scale Multitask Learning"
- Anderson & Roth (2018): "EMBER: An Open Dataset for Training Static PE Malware ML Models"
- SOREL-20M Dataset (2020): Sophos + ReversingLabs, 20M samples

AUTOR: ShadowNet Defender Team
COMPATIBLE CON: SOREL-20M feature format
"""

from .base import FeatureBlock
import pefile
import numpy as np
import hashlib


class ImportsFeatureBlock(FeatureBlock):
    """
    Extrae características de la Import Address Table (IAT) del PE usando feature hashing.
    
    Cada importación (DLL:función) se mapea a un índice determinístico en un vector
    de 1280 dimensiones usando SHA256 hash.
    
    Compatible con SOREL-20M (1280 características).
    """
    
    # Dimensión del vector de salida
    DIM = 1280
    
    @property
    def name(self) -> str:
        return "ImportsFeatureBlock"
    
    @property
    def dim(self) -> int:
        return self.DIM
    
    @staticmethod
    def _normalize_name(name: str) -> str:
        """
        Normaliza nombres de DLL/función para consistencia cross-sample.
        
        Operaciones:
        - Strip whitespace
        - Lowercase (KERNEL32.DLL → kernel32.dll)
        - Remover extensión .dll si existe
        
        Args:
            name: Nombre original (puede ser None)
            
        Returns:
            Nombre normalizado (string vacío si None)
        """
        if name is None:
            return ""
        
        # Convertir a lowercase y remover espacios
        normalized = name.strip().lower()
        
        # Remover extensión .dll si existe (para uniformidad)
        if normalized.endswith('.dll'):
            normalized = normalized[:-4]
        
        return normalized
    
    @staticmethod
    def _hash_feature(feature: str) -> int:
        """
        Calcula hash determinístico de una feature string.
        
        Usa SHA256 (hash criptográfico) para garantizar:
        - Distribución uniforme en el espacio [0, DIM-1]
        - Resistencia a patrones adversariales
        - Determinismo cross-platform
        
        Fórmula:
            hash_value = SHA256(feature)[:8]  # Primeros 8 bytes
            index = hash_value mod 1280
        
        Args:
            feature: String de la forma "dll_name:function_name"
            
        Returns:
            Índice en el rango [0, 1279]
        """
        # Calcular SHA256 hash
        digest = hashlib.sha256(feature.encode('utf-8', errors='replace')).digest()
        
        # Convertir primeros 8 bytes a entero (little-endian)
        hash_value = int.from_bytes(digest[:8], byteorder='little')
        
        # Mapear al rango [0, DIM-1] usando módulo
        return hash_value % ImportsFeatureBlock.DIM
    
    def extract(self, pe: pefile.PE, raw_data: bytes = None) -> np.ndarray:
        """
        Extrae features de la Import Table usando feature hashing.
        
        Algoritmo:
        1. Inicializar vector de ceros (1280)
        2. Para cada DLL en DIRECTORY_ENTRY_IMPORT:
            a. Normalizar nombre de DLL
            b. Para cada función importada:
                i. Normalizar nombre de función (o usar ordinal)
                ii. Crear feature string: "dll:function"
                iii. Calcular hash → índice
                iv. Incrementar contador en vector[índice]
        3. Normalizar vector (frecuencia relativa)
        
        Args:
            pe: Objeto pefile.PE analizado
            raw_data: Bytes del archivo (no utilizado, requerido por interfaz)
            
        Returns:
            Array de 1280 float32, normalizado (suma ≈ 1.0 si hay imports)
            
        Manejo de Edge Cases:
        - Sin imports: devuelve vector de ceros
        - Nombre DLL corrupto: usa "unknown"
        - Import by ordinal (sin nombre): usa "ord{N}"
        - Unicode inválido: usa errors='replace'
        """
        # Inicializar vector de contadores
        vector = np.zeros(self.DIM, dtype=np.float32)
        
        # Verificar si el PE tiene Import Table
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            # Archivo sin imports (raro pero posible)
            return vector
        
        # Iterar sobre cada DLL importada
        for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                # Decodificar nombre de DLL (puede estar en bytes)
                dll_name_bytes = dll_entry.dll
                if isinstance(dll_name_bytes, bytes):
                    dll_name = dll_name_bytes.decode('utf-8', errors='replace')
                else:
                    dll_name = str(dll_name_bytes)
                
                # Normalizar nombre de DLL
                dll_name = self._normalize_name(dll_name)
            except Exception:
                # Nombre de DLL corrupto o inválido
                dll_name = "unknown"
            
            # Iterar sobre cada función importada de esta DLL
            for func in dll_entry.imports:
                try:
                    # Verificar si la importación es por nombre o por ordinal
                    if func.name:
                        # Import by name (caso común)
                        func_name_bytes = func.name
                        if isinstance(func_name_bytes, bytes):
                            func_name = func_name_bytes.decode('utf-8', errors='replace')
                        else:
                            func_name = str(func_name_bytes)
                        
                        func_name = self._normalize_name(func_name)
                    else:
                        # Import by ordinal (sin nombre)
                        # Usar "ord{N}" como feature name
                        func_name = f"ord{func.ordinal}"
                except Exception:
                    # Nombre de función corrupto
                    func_name = "unknown"
                
                # Crear feature string: "dll:function"
                feature = f"{dll_name}:{func_name}"
                
                # Calcular hash y obtener índice
                index = self._hash_feature(feature)
                
                # Incrementar contador en el bin correspondiente
                vector[index] += 1
        
        # Normalización: convertir a frecuencia relativa
        # Esto hace el vector más robusto a PEs de diferentes tamaños
        total = vector.sum()
        if total > 0:
            vector = vector / total
        
        # Validación final (opcional, debug)
        assert vector.shape == (self.DIM,), f"Shape incorrecta: {vector.shape}"
        
        return vector
