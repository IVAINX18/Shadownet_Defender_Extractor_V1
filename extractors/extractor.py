import pefile
import numpy as np
import os
import time
from typing import List, Dict, Any

from core.errors import NonPEFileError

from extractors.base import FeatureBlock
from extractors.byte_histogram import ByteHistogram
from extractors.byte_entropy import ByteEntropy
from extractors.imports import ImportsFeatureBlock
from extractors.exports import ExportsFeatureBlock
from extractors.section_info import SectionInfoBlock
from extractors.header import HeaderFileInfo
from extractors.string_extractor import StringExtractorBlock
from extractors.general import GeneralFileInfo
from utils.logger import setup_logger

logger = setup_logger(__name__)


def read_distributed_file(file_path: str, file_size: int, limit: int = 10 * 1024 * 1024) -> bytes:
    """
    Lee 1/3 del inicio, 1/3 del centro y 1/3 del final del archivo directamente del disco.
    Evita leer todo el archivo en memoria para archivos gigantes (resistencia a OOM).
    
    Args:
        file_path: Ruta del archivo.
        file_size: Tamaño total en bytes.
        limit: Límite de bytes a leer en total (default 10MB).
        
    Returns:
        Bytes muestreados y concatenados.
    """
    if file_size <= limit:
        with open(file_path, "rb") as f:
            return f.read()

    chunk_size = limit // 3
    with open(file_path, "rb") as f:
        # Inicio
        start_chunk = f.read(chunk_size)
        
        # Centro
        mid_offset = (file_size // 2) - (chunk_size // 2)
        f.seek(mid_offset)
        mid_chunk = f.read(chunk_size)
        
        # Final
        end_offset = file_size - chunk_size
        f.seek(end_offset)
        end_chunk = f.read(chunk_size)

    return start_chunk + mid_chunk + end_chunk


class PEFeatureExtractor:
    """
    Main aggregator for PE feature extraction.
    Combines all feature blocks into a single compatible vector.

    * NOTA DE SEGURIDAD — Manejo de PEs malformados y Anti-Evasión:
        El malware real frecuentemente modifica sus cabeceras PE (PE header
        mangling) o infla archivos (file bloating) para evadir análisis estáticos.
        
        Nuestra estrategia mejorada incluye:
        1. Muestreo distribuido de archivos grandes sin lectura total en RAM.
        2. Fallback de características crudas (RAW_FALLBACK) si pefile falla completamente.
        3. Detección pasiva de packers y anomalías de compresión.
        4. Límites estrictos en número de secciones/imports/exports (resistencia DoS).
        5. Auditoría completa de cobertura para visibilidad y diagnóstico.
    """
    
    # Total dimension expected by the model/scaler (EMBER 2.0 standard)
    TOTAL_DIM = 2381

    # Canonical ranges for each feature block inside the concatenated vector.
    # Used by explanation scripts to avoid hard-coded offsets.
    BLOCK_RANGES = {
        "ByteHistogram": (0, 256),
        "ByteEntropy": (256, 512),
        "Strings": (512, 616),
        "General": (616, 626),
        "Header": (626, 688),
        "Section": (688, 943),
        "Imports": (943, 2223),
        "Exports": (2223, 2351),
    }
    
    def __init__(self):
        # Order matters! Must match training order.
        self.blocks: List[FeatureBlock] = [
            ByteHistogram(),       # 256
            ByteEntropy(),         # 256
            StringExtractorBlock(),# 104
            GeneralFileInfo(),     # 10
            HeaderFileInfo(),      # 62
            SectionInfoBlock(),    # 255
            ImportsFeatureBlock(), # 1280
            ExportsFeatureBlock()  # 128
        ]
        # Auditoría de cobertura y diagnóstico (Mejora 6)
        self.last_diagnostics: Dict[str, Any] = {}

    @staticmethod
    def _parse_pe(raw_data: bytes, file_path: str, file_size: int) -> tuple:
        """
        Intenta parsear un archivo PE con múltiples estrategias de fallback.
        Retorna una tupla (pe, modo) donde modo es "PE_STRICT" o "PE_FASTLOAD".
        """
        # Si el archivo excede los 150 MB, forzamos RAW_FALLBACK de inmediato para seguridad
        if file_size > 150 * 1024 * 1024:
            raise Exception("File size too large (> 150MB). Skipping PE parsing for safety.")

        # Estrategia 1: parseo completo estándar
        try:
            pe = pefile.PE(data=raw_data)
            return pe, "PE_STRICT"
        except Exception as e1:
            first_error_msg = str(e1)
            logger.warning(
                "pefile: parseo estricto falló para %s (%s). "
                "Intentando parseo relajado (fast_load)...",
                file_path, first_error_msg,
            )

        # Estrategia 2: parseo relajado — tolera cabeceras malformadas
        try:
            pe = pefile.PE(data=raw_data, fast_load=True)
            logger.info(
                "pefile: parseo relajado exitoso para %s.",
                file_path,
            )
            return pe, "PE_FASTLOAD"
        except Exception as e2:
            logger.error(
                "pefile: ambos modos de parseo fallaron para %s. "
                "Error estricto: %s | Error relajado: %s",
                file_path, first_error_msg, e2,
            )
            raise NonPEFileError(file_path) from e2

    def detect_packer_features(self, pe: pefile.PE, raw_data: bytes, file_size: int) -> Dict[str, Any]:
        """
        Calcula indicadores de compresión, packing y evasión para auditoría (Mejora 4).
        """
        indicators = {
            "global_entropy": 0.0,
            "ratio_virtual_real": 1.0,
            "num_sections": 0,
            "executable_sections": 0,
            "rwx_sections": 0,
            "anomalous_sections": 0,
            "num_imports": 0,
            "num_exports": 0,
            "is_packed_upx": False,
            "high_entropy_sections": 0,
            "packer_detected": False,
            "packer_reasons": []
        }

        # Entropía global
        if raw_data:
            from extractors._math_utils import calculate_shannon_entropy
            indicators["global_entropy"] = round(calculate_shannon_entropy(raw_data), 4)
            if indicators["global_entropy"] > 7.2:
                indicators["packer_reasons"].append("high_global_entropy")
            
            # Firma UPX en bytes crudos
            if b"UPX!" in raw_data:
                indicators["is_packed_upx"] = True
                indicators["packer_reasons"].append("upx_signature_in_bytes")

        if pe is None:
            indicators["packer_detected"] = len(indicators["packer_reasons"]) > 0
            return indicators

        try:
            # Secciones
            sections = pe.sections
            indicators["num_sections"] = len(sections)
            
            total_raw_size = 0
            total_virt_size = 0
            
            for section in sections[:96]:  # Límite anti-DoS
                r_size = section.SizeOfRawData
                v_size = section.Misc_VirtualSize
                total_raw_size += r_size
                total_virt_size += v_size
                
                # Nombre anómalo
                try:
                    name = section.Name.decode('utf-8', errors='ignore').strip().replace('\x00', '')
                except Exception:
                    name = ""
                
                if name:
                    standard_names = {".text", ".data", ".rdata", ".reloc", ".rsrc", ".pdata", ".tls", ".didat", ".gfids"}
                    if name.lower() not in standard_names:
                        indicators["anomalous_sections"] += 1
                        if "upx" in name.lower():
                            indicators["is_packed_upx"] = True
                            indicators["packer_reasons"].append("upx_section_name")
                
                # Entropía por sección
                try:
                    sect_data = section.get_data()
                    from extractors._math_utils import calculate_shannon_entropy
                    s_entropy = calculate_shannon_entropy(sect_data)
                    if s_entropy > 7.2:
                        indicators["high_entropy_sections"] += 1
                except Exception:
                    pass
                
                # Permisos ejecutables / RWX
                props = getattr(section, 'Characteristics', 0)
                is_exec = (props & 0x20000000) > 0
                is_read = (props & 0x40000000) > 0
                is_write = (props & 0x80000000) > 0
                
                if is_exec:
                    indicators["executable_sections"] += 1
                if is_exec and is_read and is_write:
                    indicators["rwx_sections"] += 1
                    indicators["packer_reasons"].append("rwx_section_present")

            # Ratio virtual/raw
            if total_raw_size > 0:
                ratio = total_virt_size / total_raw_size
                indicators["ratio_virtual_real"] = round(ratio, 4)
                if ratio > 3.0:
                    indicators["packer_reasons"].append("high_virtual_to_raw_ratio")
            elif total_virt_size > 0:
                indicators["ratio_virtual_real"] = 999.0
                indicators["packer_reasons"].append("zero_raw_size_with_virtual_size")

            # Imports / Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                indicators["num_imports"] = sum([len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT[:100]])
                if indicators["num_imports"] < 10:
                    indicators["packer_reasons"].append("very_low_imports_count")
            else:
                indicators["packer_reasons"].append("no_imports")

            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                indicators["num_exports"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

            if indicators["high_entropy_sections"] > 0 and indicators["num_imports"] < 15:
                indicators["packer_reasons"].append("high_entropy_with_low_imports")

        except Exception as e:
            indicators["packer_reasons"].append(f"error_during_analysis: {str(e)}")

        indicators["packer_detected"] = len(indicators["packer_reasons"]) > 0
        return indicators

    def extract_dict(self, file_path: str) -> Dict[str, np.ndarray]:
        """Returns features as a dictionary (useful for debugging)."""
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:
                raw_data = read_distributed_file(file_path, file_size)
            else:
                with open(file_path, "rb") as f:
                    raw_data = f.read()

            # Parsear pe con headers solamente
            pe_data_for_parsing = raw_data
            if file_size > 10 * 1024 * 1024:
                with open(file_path, "rb") as f:
                    pe_data_for_parsing = f.read(10 * 1024 * 1024)

            pe = None
            try:
                pe, _ = self._parse_pe(pe_data_for_parsing, file_path, file_size)
            except Exception:
                pass # Tolerante a fallos
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return {}

        results = {}
        for block in self.blocks:
            try:
                if pe is None:
                    if block.name in ["ByteHistogram", "ByteEntropy", "StringExtractorBlock"]:
                        results[block.name] = block.extract(None, raw_data)
                    elif block.name == "GeneralFileInfo":
                        feats = np.zeros(block.dim, dtype=np.float32)
                        feats[0] = float(file_size)
                        results[block.name] = feats
                    else:
                        results[block.name] = np.zeros(block.dim, dtype=np.float32)
                else:
                    results[block.name] = block.extract(pe, raw_data)
            except Exception as e:
                logger.warning(f"Error extracting {block.name}: {e}")
                results[block.name] = np.zeros(block.dim, dtype=np.float32)
                
        if pe is not None:
            pe.close()
        return results

    def extract(self, file_path: str) -> np.ndarray:
        """
        Extracts the full concatenated feature vector.
        Implementa RAW_FALLBACK, muestreo distribuido y auditoría de cobertura.
        """
        start_time = time.time()
        final_vector = np.zeros(self.TOTAL_DIM, dtype=np.float32)
        
        try:
            file_size = os.path.getsize(file_path)
        except Exception as exc:
            raise NonPEFileError(file_path) from exc

        if file_size == 0:
            raise NonPEFileError(file_path)

        # 1. Muestreo distribuido de bytes para análisis crudo (Mejora 1)
        try:
            raw_data = read_distributed_file(file_path, file_size)
        except Exception as exc:
            raise NonPEFileError(file_path) from exc

        # 2. Parseo de cabeceras PE (Mejora 5 / Evasión de tamaño)
        # Cargamos los primeros 10 MB del archivo en disco para el parseo PE (suficiente para todos los headers)
        pe = None
        mode = "PE_STRICT"
        degradation_reason = None

        if file_size > 150 * 1024 * 1024:
            mode = "RAW_FALLBACK"
            degradation_reason = "file_size_exceeded_150mb"
        else:
            try:
                # Si el archivo es grande (>10MB), leemos solo los primeros 10MB para el parseo PE
                if file_size > 10 * 1024 * 1024:
                    with open(file_path, "rb") as f:
                        pe_data_for_parsing = f.read(10 * 1024 * 1024)
                    pe, mode = self._parse_pe(pe_data_for_parsing, file_path, file_size)
                    # Forzar a PE_FASTLOAD debido al límite de tamaño de lectura
                    mode = "PE_FASTLOAD"
                    degradation_reason = "file_size_exceeded_10mb"
                else:
                    pe, mode = self._parse_pe(raw_data, file_path, file_size)
            except Exception as e:
                # Fallback de características crudas si falla el parseo PE (Mejora 2)
                pe = None
                mode = "RAW_FALLBACK"
                degradation_reason = f"pefile_failed: {str(e)}"

        # 3. Extracción por bloques en cascada tolerante a fallos
        current_offset = 0
        for block in self.blocks:
            try:
                if pe is None:
                    # En modo RAW_FALLBACK solo extraemos lo mínimo de emergencia compatible
                    if block.name in ["ByteHistogram", "ByteEntropy", "StringExtractorBlock"]:
                        feats = block.extract(None, raw_data)
                    elif block.name == "GeneralFileInfo":
                        # Conservar el tamaño del archivo en la primera posición del vector General (compatibilidad)
                        feats = np.zeros(block.dim, dtype=np.float32)
                        feats[0] = float(file_size)
                    else:
                        feats = np.zeros(block.dim, dtype=np.float32)
                else:
                    feats = block.extract(pe, raw_data)
                
                # Validación de dimensiones
                if len(feats) != block.dim:
                    padded = np.zeros(block.dim, dtype=np.float32)
                    min_len = min(len(feats), block.dim)
                    padded[:min_len] = feats[:min_len]
                    feats = padded
                
                end_offset = current_offset + block.dim
                final_vector[current_offset : end_offset] = feats
                current_offset = end_offset
                
            except Exception as e:
                logger.warning(
                    "Block %s failed for %s (offset %d): %s. Using zeros.",
                    block.name, file_path, current_offset, e,
                )
                final_vector[current_offset : current_offset + block.dim] = 0.0
                current_offset += block.dim

        # Detección de Packers para auditoría
        packer_info = self.detect_packer_features(pe, raw_data, file_size)

        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass

        # 4. Generación de métricas de cobertura y auditoría (Mejora 6)
        elapsed_time = time.time() - start_time
        bytes_sampled = len(raw_data)
        percentage_analyzed = (bytes_sampled / file_size) * 100.0 if file_size > 0 else 0.0

        self.last_diagnostics = {
            "diagnostics": {
                "file_size_bytes": file_size,
                "bytes_sampled": bytes_sampled,
                "percentage_analyzed": round(percentage_analyzed, 2),
                "extraction_mode": mode,
                "degradation_reason": degradation_reason,
                "extraction_time_ms": round(elapsed_time * 1000, 2),
                "packer_indicators": packer_info,
            }
        }

        # Registrar la métrica de cobertura y modo
        logger.info(
            "Extracción completada: %s | modo=%s | ratio_analizado=%.1f%% | packer_detectado=%s | tiempo=%.1fms",
            os.path.basename(file_path),
            mode,
            percentage_analyzed,
            packer_info["packer_detected"],
            elapsed_time * 1000,
        )

        return final_vector
