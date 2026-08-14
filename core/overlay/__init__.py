"""
core/overlay/__init__.py — Analizador forense de overlay PE.

El overlay de un archivo PE es todo el contenido ubicado después del
final de la última sección definida en el PE Header. Es una zona
invisible para el Windows loader pero completamente accesible para
cualquier proceso que lea el archivo desde disco.

Técnica de evasión documentada:
    Droppers modernos almacenan el payload cifrado (RC4/AES/XOR) en
    el overlay. El stub PE —pequeño y aparentemente benigno— se encarga
    de leer, descifrar y cargar el payload en memoria mediante
    Process Hollowing o similares. El extractor estático solo ve el stub.

Ejemplo real identificado en este proyecto:
    - Archivo total: 20.9 MB
    - Stub PE: 0.3 MB (1.3% del archivo)
    - Overlay cifrado: 19.7 MB (98.7%, entropía 7.99/8.0)
    - PE embebido en overlay @ offset +108,189 (también cifrado)
    - Resultado ML: BENIGN — porque las features eran del stub
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import numpy as np
import pefile

from utils.logger import setup_logger

logger = setup_logger(__name__)

# Máximo de bytes del overlay a analizar para entropía y strings
_MAX_OVERLAY_ANALYSIS = 5 * 1024 * 1024   # 5 MB
# Máximo de bytes del overlay para búsqueda de firmas MZ
_MAX_MZ_SEARCH = 20 * 1024 * 1024          # 20 MB

# Regex para strings ASCII imprimibles en overlay
_REGEX_ASCII = re.compile(rb'[\x20-\x7E]{6,}')

# Strings sospechosas a buscar en el overlay
_SUSPICIOUS_STRINGS = [
    b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory",
    b"NtCreateThread", b"RtlCreateUserThread", b"NtUnmapViewOfSection",
    b"ShellExecute", b"WinExec", b"cmd.exe", b"powershell",
    b"regsvr32", b"rundll32", b"http://", b"https://",
    b"bitcoin", b"wallet", b"ransomware", b"mimikatz",
]

# Firmas de instaladores legítimos (protección contra falsos positivos)
_INSTALLER_SIGNATURES = {
    b"NullsoftInst":       "NSIS",
    b"Inno Setup":         "InnoSetup",
    b"InstallShield":      "InstallShield",
    b"WinZip Self-Extractor": "WinZip SFX",
    b"7-Zip":              "7-Zip SFX",
    b"MSCF":               "CAB/MSI",
    b"PK\x03\x04":         "ZIP/SFX",
    b"Rar!\x1a\x07":       "RAR SFX",
    b"AutoHotkey":         "AutoHotkey SFX",
    b"Setup":              None,  # Requiere confirmación adicional
}


@dataclass
class EmbeddedPEInfo:
    """Información de un PE encontrado dentro del overlay."""
    offset_in_overlay: int
    estimated_size: int
    entropy: float
    structurally_valid: bool

    def to_dict(self) -> dict:
        return {
            "offset_in_overlay": self.offset_in_overlay,
            "estimated_size": self.estimated_size,
            "entropy": round(self.entropy, 4),
            "structurally_valid": self.structurally_valid,
        }


@dataclass
class OverlayReport:
    """Informe forense completo del overlay de un archivo PE."""

    # Presencia y tamaño
    overlay_present: bool = False
    overlay_offset: int = 0
    overlay_size: int = 0
    overlay_ratio: float = 0.0

    # Entropía
    overlay_entropy: float = 0.0
    global_entropy: float = 0.0

    # PEs embebidos
    embedded_pe_detected: bool = False
    embedded_pe_count: int = 0
    embedded_pe_offsets: List[int] = field(default_factory=list)
    embedded_pe_details: List[EmbeddedPEInfo] = field(default_factory=list)

    # Strings en el overlay
    overlay_has_strings: bool = False
    overlay_string_count: int = 0
    overlay_suspicious_strings: List[str] = field(default_factory=list)

    # Protección contra falsos positivos
    is_known_installer: bool = False
    installer_type: Optional[str] = None

    # Resultados YARA (rellenos externamente por el engine)
    overlay_yara_hits: List[str] = field(default_factory=list)
    embedded_pe_yara_hits: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overlay_present": self.overlay_present,
            "overlay_offset": self.overlay_offset,
            "overlay_size": self.overlay_size,
            "overlay_ratio": round(self.overlay_ratio, 4),
            "overlay_entropy": round(self.overlay_entropy, 4),
            "global_entropy": round(self.global_entropy, 4),
            "embedded_pe_detected": self.embedded_pe_detected,
            "embedded_pe_count": self.embedded_pe_count,
            "embedded_pe_offsets": self.embedded_pe_offsets,
            "embedded_pe_details": [e.to_dict() for e in self.embedded_pe_details],
            "overlay_has_strings": self.overlay_has_strings,
            "overlay_string_count": self.overlay_string_count,
            "overlay_suspicious_strings": self.overlay_suspicious_strings[:10],
            "is_known_installer": self.is_known_installer,
            "installer_type": self.installer_type,
            "overlay_yara_hits": self.overlay_yara_hits,
            "embedded_pe_yara_hits": self.embedded_pe_yara_hits,
        }


class OverlayAnalyzer:
    """
    Analizador forense de overlay PE.

    Detecta y caracteriza contenido oculto después del final de las
    secciones PE, incluyendo payloads cifrados y PEs embebidos.
    """

    def analyze(self, raw_data: bytes, pe: Optional[pefile.PE] = None) -> OverlayReport:
        """
        Analiza el overlay de un archivo PE.

        Args:
            raw_data: Bytes completos del archivo.
            pe: Objeto pefile.PE ya parseado (opcional, para mayor precisión).

        Returns:
            OverlayReport con todos los hallazgos.
        """
        report = OverlayReport()
        total_size = len(raw_data)

        if total_size == 0:
            return report

        # Entropía global del archivo completo
        report.global_entropy = self._entropy(raw_data[:_MAX_OVERLAY_ANALYSIS])

        # Detectar instaladores legítimos antes de cualquier análisis
        self._detect_installer(raw_data, report)

        # Calcular offset del overlay
        overlay_offset = self._find_overlay_offset(raw_data, pe)
        if overlay_offset <= 0 or overlay_offset >= total_size:
            return report

        overlay_data = raw_data[overlay_offset:]
        overlay_size = len(overlay_data)

        # Overlays < 512 bytes no son significativos
        if overlay_size < 512:
            return report

        report.overlay_present = True
        report.overlay_offset = overlay_offset
        report.overlay_size = overlay_size
        report.overlay_ratio = overlay_size / total_size

        # Entropía del overlay
        analysis_slice = overlay_data[:_MAX_OVERLAY_ANALYSIS]
        report.overlay_entropy = self._entropy(analysis_slice)

        # Buscar PEs embebidos
        self._find_embedded_pes(overlay_data, report)

        # Buscar strings sospechosas
        self._find_suspicious_strings(analysis_slice, report)

        logger.info(
            "Overlay analizado — size=%.1fMB ratio=%.1f%% entropy=%.4f "
            "embedded_pe=%d installer=%s suspicious_strings=%d",
            overlay_size / 1024 / 1024,
            report.overlay_ratio * 100,
            report.overlay_entropy,
            report.embedded_pe_count,
            report.installer_type or "no",
            len(report.overlay_suspicious_strings),
        )

        return report

    # ------------------------------------------------------------------
    # Implementación interna
    # ------------------------------------------------------------------

    def _find_overlay_offset(self, raw_data: bytes, pe: Optional[pefile.PE]) -> int:
        """Calcula el offset donde comienza el overlay (fin de la última sección)."""

        # Método 1: usar pefile si disponible (más preciso)
        if pe is not None:
            try:
                max_offset = 0
                for section in pe.sections:
                    end = section.PointerToRawData + section.SizeOfRawData
                    if end > max_offset:
                        max_offset = end
                if max_offset > 0:
                    return max_offset
            except Exception:
                pass

        # Método 2: parseo manual del PE header
        try:
            if len(raw_data) < 64 or raw_data[:2] != b"MZ":
                return 0

            e_lfanew = struct.unpack_from("<I", raw_data, 0x3C)[0]
            if e_lfanew + 4 > len(raw_data):
                return 0
            if raw_data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
                return 0

            num_sections = struct.unpack_from("<H", raw_data, e_lfanew + 6)[0]
            optional_header_size = struct.unpack_from("<H", raw_data, e_lfanew + 20)[0]
            section_table_offset = e_lfanew + 24 + optional_header_size

            max_end = 0
            for i in range(min(num_sections, 96)):
                sec_off = section_table_offset + i * 40
                if sec_off + 40 > len(raw_data):
                    break
                ptr_raw = struct.unpack_from("<I", raw_data, sec_off + 20)[0]
                size_raw = struct.unpack_from("<I", raw_data, sec_off + 16)[0]
                if ptr_raw + size_raw > max_end:
                    max_end = ptr_raw + size_raw

            return max_end
        except Exception:
            return 0

    def _find_embedded_pes(self, overlay_data: bytes, report: OverlayReport) -> None:
        """Busca firmas MZ/PE válidas dentro del overlay."""
        search_data = overlay_data[:_MAX_MZ_SEARCH]
        offset = 0

        while True:
            idx = search_data.find(b"MZ", offset)
            if idx < 0:
                break

            if idx + 64 <= len(search_data):
                try:
                    e_lfanew = struct.unpack_from("<I", search_data, idx + 0x3C)[0]
                    # e_lfanew razonable para un PE real
                    if 0x20 < e_lfanew < 0x1000:
                        pe_sig_off = idx + e_lfanew
                        if (pe_sig_off + 4 <= len(search_data) and
                                search_data[pe_sig_off:pe_sig_off + 4] == b"PE\x00\x00"):

                            estimated_size = len(overlay_data) - idx
                            fragment = overlay_data[idx:idx + min(estimated_size, _MAX_OVERLAY_ANALYSIS)]
                            entropy = self._entropy(fragment)

                            # Intentar parsear para validar la estructura
                            valid = False
                            try:
                                pe_test = pefile.PE(
                                    data=fragment[:min(len(fragment), 2_000_000)],
                                    fast_load=True,
                                )
                                valid = True
                                pe_test.close()
                            except Exception:
                                pass

                            report.embedded_pe_offsets.append(idx)
                            report.embedded_pe_details.append(EmbeddedPEInfo(
                                offset_in_overlay=idx,
                                estimated_size=estimated_size,
                                entropy=entropy,
                                structurally_valid=valid,
                            ))

                            logger.info(
                                "PE embebido en overlay @ offset +%d | "
                                "entropy=%.4f | structurally_valid=%s",
                                idx, entropy, valid,
                            )
                except Exception:
                    pass

            offset = idx + 2

        report.embedded_pe_count = len(report.embedded_pe_offsets)
        report.embedded_pe_detected = report.embedded_pe_count > 0

    def _find_suspicious_strings(self, data: bytes, report: OverlayReport) -> None:
        """Busca strings ASCII y patrones sospechosos en el overlay."""
        strings = _REGEX_ASCII.findall(data)
        report.overlay_string_count = len(strings)
        report.overlay_has_strings = len(strings) > 0

        found = set()
        for sig in _SUSPICIOUS_STRINGS:
            sig_lower = sig.lower()
            for s in strings[:5000]:
                if sig_lower in s.lower():
                    decoded = s.decode("utf-8", errors="replace")[:120]
                    if decoded not in found:
                        found.add(decoded)
                        report.overlay_suspicious_strings.append(decoded)
                    break

    def _detect_installer(self, raw_data: bytes, report: OverlayReport) -> None:
        """Detecta instaladores legítimos para reducir falsos positivos."""
        search_zone = raw_data[:min(len(raw_data), 10_000_000)]
        for sig, installer_type in _INSTALLER_SIGNATURES.items():
            if sig in search_zone and installer_type is not None:
                report.is_known_installer = True
                report.installer_type = installer_type
                logger.info("Instalador legítimo detectado: %s (FP protection activa)", installer_type)
                return

    @staticmethod
    def _entropy(data: bytes) -> float:
        """Entropía de Shannon de una secuencia de bytes."""
        if not data:
            return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts / len(data)
        probs = probs[probs > 0]
        return float(-np.sum(probs * np.log2(probs)))
