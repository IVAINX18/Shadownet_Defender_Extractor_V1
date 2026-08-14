"""
core/dotnet/__init__.py — Analizador especializado para ensamblados .NET / CLR.

Mejoras implementadas:
    Mejora 1 — DotNetAnalyzer: detecta CLR Header, metadata, versión, assembly info.
    Mejora 3 — Detección de ofuscadores: ConfuserEx, Dotfuscator, SmartAssembly, etc.
    Mejora 4 — Embedded Assemblies Detection: DLLs y payloads en recursos .NET.
    Mejora 5 — Suspicious IL Indicators: Reflection, P/Invoke dinámico, loaders.
    Mejora 6 — DotNet Risk Profile: score y nivel de riesgo específico para .NET.

Compatibilidad garantizada:
    - No modifica el vector de 2381 features.
    - No modifica el scaler ni la inferencia ONNX.
    - Actúa exclusivamente como capa heurística/diagnóstica/forense.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import setup_logger

logger = setup_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constantes de detección
# ──────────────────────────────────────────────────────────────────────────────

# Firmas de ofuscadores .NET (strings embebidas en los ensamblados)
_OBFUSCATOR_SIGNATURES: Dict[str, List[bytes]] = {
    "ConfuserEx": [
        b"ConfuserEx", b"ConfusedByAttribute",
        b"Confuser.Core", b"confuserex",
    ],
    "Dotfuscator": [
        b"Dotfuscator", b"DotfuscatorAttribute",
        b"PreEmptive", b"DotfuscatedAssembly",
    ],
    "SmartAssembly": [
        b"SmartAssembly", b"SA_Protected",
        b"Obfuscated by SmartAssembly",
        b"[Obfuscation(", b"ObfuscatedByGoliath",
    ],
    "Eazfuscator": [
        b"Eazfuscator", b"GrEmit",
        b"obfuscated by Eazfuscator",
    ],
    "Agile.NET": [
        b"Agile.NET", b"agileDotNet",
        b"Spices.Obfuscator", b"Agile",
    ],
    "Babel Obfuscator": [
        b"Babel Obfuscator", b"BabelObfuscator",
        b"Babel.Obfuscator",
    ],
    "de4dot": [
        b"de4dot", b"de4dot.code",
    ],
    "Crypto Obfuscator": [
        b"LogicNP", b"Crypto Obfuscator",
    ],
    "Obfuscar": [
        b"Obfuscar",
    ],
    "dnSpy": [
        b"dnSpy.Debugger",
    ],
}

# Patrones de metadata anómala que indican ofuscación
_OBFUSCATOR_METADATA_PATTERNS: List[re.Pattern] = [
    re.compile(rb'\x00[\x01-\x1f]{4,}'),          # Caracteres de control en nombres
    re.compile(rb'[a-zA-Z]\x00[a-zA-Z]\x00'),      # Strings Unicode con caracteres raros
    re.compile(rb'[\x80-\xFF]{3,}'),               # High-byte sequences (Unicode obfuscado)
]

# Patrones de IL sospechosos — APIs peligrosas en strings .NET
_SUSPICIOUS_IL_PATTERNS: List[bytes] = [
    # Reflection y carga dinámica
    b"Reflection", b"Assembly.Load", b"LoadFrom", b"LoadFile",
    b"GetManifestResourceStream", b"GetTypes", b"InvokeMember",
    b"CreateInstance", b"Activator.CreateInstance",
    # P/Invoke dinámico y memory injection
    b"VirtualAlloc", b"VirtualAllocEx", b"WriteProcessMemory",
    b"CreateRemoteThread", b"NtCreateThread", b"RtlCreateUserThread",
    b"GetProcAddress", b"LoadLibrary",
    # Process spawning
    b"Process.Start", b"ProcessStartInfo", b"CreateProcess",
    b"ShellExecute", b"WScript.Shell",
    # PowerShell / scripting
    b"PowerShell", b"Runspace", b"RunspaceFactory",
    b"IEX", b"Invoke-Expression",
    # Network / C2
    b"WebClient", b"DownloadString", b"DownloadFile",
    b"HttpClient", b"WebRequest", b"Net.Sockets",
    # Evasión
    b"AntiDebug", b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
    b"Environment.Exit", b"Marshal.GetDelegateForFunctionPointer",
    # Credential / keylog
    b"GetAsyncKeyState", b"SetWindowsHookEx",
    b"CredentialManager", b"SecretString",
]

# MZ signature para detectar PEs embebidos en recursos
_MZ_SIGNATURE = b"MZ"
_PE_SIGNATURE = b"PE\x00\x00"

# Tamaño mínimo de un recurso para considerarlo como posible PE embebido
_MIN_EMBEDDED_PE_SIZE = 1024  # 1 KB

# CLR Flags
_COMIMAGE_FLAGS_ILONLY          = 0x00000001
_COMIMAGE_FLAGS_32BITREQUIRED   = 0x00000002
_COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008
_COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010


# ──────────────────────────────────────────────────────────────────────────────
# Dataclasses de resultado
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class DotNetObfuscatorInfo:
    """Información sobre ofuscador detectado."""
    detected: bool = False
    name: str = ""
    confidence: str = "LOW"    # LOW / MEDIUM / HIGH
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "obfuscator_detected": self.detected,
            "obfuscator_name": self.name,
            "obfuscator_confidence": self.confidence,
            "obfuscator_evidence": self.evidence,
        }


@dataclass
class DotNetAssemblyInfo:
    """Información estructural del ensamblado CLR."""
    # CLR Header
    clr_version: str = ""
    clr_flags: int = 0
    clr_flags_text: List[str] = field(default_factory=list)
    metadata_rva: int = 0
    metadata_size: int = 0
    # Assembly metadata
    assembly_name: str = ""
    assembly_version: str = ""
    culture: str = "neutral"
    public_key_token: str = ""
    has_strong_name: bool = False
    # Assembly type
    is_il_only: bool = False
    is_32bit_required: bool = False
    is_native_entrypoint: bool = False
    assembly_type: str = ""    # "Pure IL" / "Mixed Mode" / "Native AOT"
    # Code metrics
    il_size_bytes: int = 0
    method_count: int = 0
    type_count: int = 0
    # Streams
    metadata_streams: List[str] = field(default_factory=list)
    # Resources
    embedded_resource_count: int = 0
    embedded_resource_names: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "clr_version": self.clr_version,
            "clr_flags": hex(self.clr_flags),
            "clr_flags_text": self.clr_flags_text,
            "assembly_name": self.assembly_name,
            "assembly_version": self.assembly_version,
            "culture": self.culture,
            "public_key_token": self.public_key_token,
            "has_strong_name": self.has_strong_name,
            "is_il_only": self.is_il_only,
            "is_32bit_required": self.is_32bit_required,
            "assembly_type": self.assembly_type,
            "il_size_bytes": self.il_size_bytes,
            "method_count": self.method_count,
            "type_count": self.type_count,
            "metadata_streams": self.metadata_streams,
            "embedded_resource_count": self.embedded_resource_count,
            "embedded_resource_names": self.embedded_resource_names,
        }


@dataclass
class DotNetEmbeddedInfo:
    """Información sobre assemblies / PEs embebidos en recursos."""
    embedded_assemblies_count: int = 0
    embedded_resources_count: int = 0
    embedded_pe_detected: bool = False
    embedded_pe_offsets: List[int] = field(default_factory=list)
    compressed_resources: int = 0
    suspicious_resource_names: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "embedded_assemblies_count": self.embedded_assemblies_count,
            "embedded_resources_count": self.embedded_resources_count,
            "embedded_pe_detected": self.embedded_pe_detected,
            "embedded_pe_offsets": self.embedded_pe_offsets,
            "compressed_resources": self.compressed_resources,
            "suspicious_resource_names": self.suspicious_resource_names,
        }


@dataclass
class DotNetSuspiciousILInfo:
    """Indicadores heurísticos de comportamiento malicioso en IL / strings .NET."""
    reflection_usage: bool = False
    dynamic_loading_detected: bool = False
    pinvoke_injection_apis: List[str] = field(default_factory=list)
    process_spawn_detected: bool = False
    powershell_detected: bool = False
    network_api_detected: bool = False
    antidebug_detected: bool = False
    suspicious_strings: List[str] = field(default_factory=list)
    il_risk_score: int = 0

    def to_dict(self) -> dict:
        return {
            "reflection_usage": self.reflection_usage,
            "dynamic_loading_detected": self.dynamic_loading_detected,
            "pinvoke_injection_apis": self.pinvoke_injection_apis,
            "process_spawn_detected": self.process_spawn_detected,
            "powershell_detected": self.powershell_detected,
            "network_api_detected": self.network_api_detected,
            "antidebug_detected": self.antidebug_detected,
            "suspicious_strings_count": len(self.suspicious_strings),
            "il_risk_score": self.il_risk_score,
        }


@dataclass
class DotNetRiskProfile:
    """Perfil de riesgo específico para malware .NET (Mejora 6)."""
    dotnet_risk_score: int = 0
    dotnet_risk_level: str = "LOW"    # LOW / MEDIUM / HIGH / CRITICAL
    risk_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "dotnet_risk_score": self.dotnet_risk_score,
            "dotnet_risk_level": self.dotnet_risk_level,
            "dotnet_risk_factors": self.risk_factors,
        }


@dataclass
class DotNetReport:
    """Informe completo del análisis .NET — agrega todos los sub-análisis."""
    is_dotnet: bool = False
    assembly_info: DotNetAssemblyInfo = field(default_factory=DotNetAssemblyInfo)
    obfuscator: DotNetObfuscatorInfo = field(default_factory=DotNetObfuscatorInfo)
    embedded: DotNetEmbeddedInfo = field(default_factory=DotNetEmbeddedInfo)
    suspicious_il: DotNetSuspiciousILInfo = field(default_factory=DotNetSuspiciousILInfo)
    risk_profile: DotNetRiskProfile = field(default_factory=DotNetRiskProfile)
    error: str = ""

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {"is_dotnet": self.is_dotnet}
        if self.error:
            d["error"] = self.error
        if self.is_dotnet:
            d.update(self.assembly_info.to_dict())
            d.update(self.obfuscator.to_dict())
            d.update(self.embedded.to_dict())
            d.update(self.suspicious_il.to_dict())
            d.update(self.risk_profile.to_dict())
        return d


# ──────────────────────────────────────────────────────────────────────────────
# DotNetAnalyzer — Clase principal
# ──────────────────────────────────────────────────────────────────────────────

class DotNetAnalyzer:
    """
    Analizador especializado para ensamblados .NET / CLR.

    No modifica el vector de 2381 features ni el pipeline ONNX.
    Opera como capa adicional de análisis forense independiente.

    Uso:
        analyzer = DotNetAnalyzer()
        report = analyzer.analyze(raw_data, pe_obj)
        if report.is_dotnet:
            print(report.to_dict())
    """

    # ── Pesos para el DotNet Risk Profile ─────────────────────────────
    _RISK_WEIGHTS: Dict[str, int] = {
        # Ofuscación
        "obfuscator_detected":          20,
        "obfuscator_metadata_anomaly":  10,
        # Recursos embebidos sospechosos
        "embedded_pe_in_resources":     35,
        "embedded_assembly":            25,
        "compressed_resources":         10,
        "suspicious_resource_names":    10,
        # IL sospechoso
        "reflection_usage":              8,
        "dynamic_loading":              15,
        "pinvoke_injection":            20,
        "process_spawn":                15,
        "powershell":                   20,
        "network_apis":                 10,
        "antidebug":                    12,
        # Entropy anómala en un .NET puro (más de lo esperado)
        "anomalous_entropy_dotnet":     10,
    }

    _RISK_THRESHOLDS: Dict[str, tuple] = {
        "LOW":      (0,   15),
        "MEDIUM":   (16,  40),
        "HIGH":     (41,  70),
        "CRITICAL": (71, 9999),
    }

    def analyze(self, raw_data: bytes, pe_obj=None) -> DotNetReport:
        """
        Analiza un archivo PE buscando indicadores de .NET.

        Args:
            raw_data: Bytes completos del archivo PE.
            pe_obj:   Objeto pefile.PE ya parseado (opcional, evita re-parseo).

        Returns:
            DotNetReport con todos los hallazgos. is_dotnet=False si no es CLR.
        """
        report = DotNetReport()

        try:
            import pefile  # Import local para no romper si no está instalado

            pe = pe_obj
            if pe is None:
                try:
                    pe = pefile.PE(data=raw_data, fast_load=True)
                    pe.parse_data_directories(
                        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
                    )
                except Exception as e:
                    logger.debug("DotNetAnalyzer: no se pudo parsear PE: %s", e)
                    return report

            # ── Verificar COM Descriptor (CLR Header) ─────────────────
            if not self._has_clr_header(pe):
                return report  # No es .NET

            report.is_dotnet = True
            logger.info("DotNetAnalyzer: ensamblado .NET/CLR detectado")

            # ── Análisis de assembly info ──────────────────────────────
            report.assembly_info = self._extract_assembly_info(pe, raw_data)

            # ── Detección de ofuscadores ───────────────────────────────
            report.obfuscator = self._detect_obfuscator(raw_data, report.assembly_info)

            # ── Embedded assemblies / PEs en recursos ──────────────────
            report.embedded = self._detect_embedded(pe, raw_data)

            # ── Indicadores IL sospechosos ─────────────────────────────
            report.suspicious_il = self._detect_suspicious_il(raw_data)

            # ── Risk Profile ───────────────────────────────────────────
            report.risk_profile = self._build_risk_profile(
                report.assembly_info,
                report.obfuscator,
                report.embedded,
                report.suspicious_il,
                raw_data,
            )

        except Exception as exc:
            logger.error("DotNetAnalyzer: error inesperado: %s", exc)
            report.error = str(exc)

        return report

    # ──────────────────────────────────────────────────────────────────
    # Detección CLR Header
    # ──────────────────────────────────────────────────────────────────

    def _has_clr_header(self, pe) -> bool:
        """Detecta si el PE tiene CLR Header / COM Descriptor."""
        try:
            # Método 1: DATA_DIRECTORY[14] presente con RVA/Size válidos
            if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
                clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
                if clr_dir.VirtualAddress != 0 and clr_dir.Size != 0:
                    return True
            # Método 2: Estructura DIRECTORY_ENTRY_COM_DESCRIPTOR
            if hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR"):
                return True
        except (IndexError, AttributeError):
            pass
        return False


    # ──────────────────────────────────────────────────────────────────
    # Mejora 1: Extracción de assembly info
    # ──────────────────────────────────────────────────────────────────

    def _extract_assembly_info(self, pe, raw_data: bytes) -> DotNetAssemblyInfo:
        """Extrae información del CLR Header y metadata streams."""
        info = DotNetAssemblyInfo()

        try:
            com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]

            # Leer CLR Header manualmente desde los bytes del PE
            clr_offset = pe.get_offset_from_rva(com.VirtualAddress)
            if clr_offset and clr_offset + 72 <= len(raw_data):
                clr_data = raw_data[clr_offset:clr_offset + 72]

                # CLR Header estructura (IMAGE_COR20_HEADER):
                # DWORD cb, WORD MajorRuntimeVersion, WORD MinorRuntimeVersion,
                # IMAGE_DATA_DIRECTORY MetaData, DWORD Flags, ...
                if len(clr_data) >= 16:
                    cb = struct.unpack_from("<I", clr_data, 0)[0]
                    major = struct.unpack_from("<H", clr_data, 4)[0]
                    minor = struct.unpack_from("<H", clr_data, 6)[0]
                    meta_rva = struct.unpack_from("<I", clr_data, 8)[0]
                    meta_size = struct.unpack_from("<I", clr_data, 12)[0]

                    info.clr_version = f"{major}.{minor}"
                    info.metadata_rva = meta_rva
                    info.metadata_size = meta_size

                if len(clr_data) >= 20:
                    flags = struct.unpack_from("<I", clr_data, 16)[0]
                    info.clr_flags = flags
                    info.clr_flags_text = self._parse_clr_flags(flags)
                    info.is_il_only = bool(flags & _COMIMAGE_FLAGS_ILONLY)
                    info.is_32bit_required = bool(flags & _COMIMAGE_FLAGS_32BITREQUIRED)
                    info.has_strong_name = bool(flags & _COMIMAGE_FLAGS_STRONGNAMESIGNED)
                    info.is_native_entrypoint = bool(flags & _COMIMAGE_FLAGS_NATIVE_ENTRYPOINT)

                    if info.is_il_only:
                        info.assembly_type = "Pure IL"
                    elif info.is_native_entrypoint:
                        info.assembly_type = "Native AOT"
                    else:
                        info.assembly_type = "Mixed Mode"

            # Leer metadata signature "BSJB" y version string
            if info.metadata_rva:
                try:
                    meta_offset = pe.get_offset_from_rva(info.metadata_rva)
                    if meta_offset and meta_offset + 20 <= len(raw_data):
                        meta_data = raw_data[meta_offset:meta_offset + 256]
                        streams, clr_ver, method_c, type_c = self._parse_metadata_header(
                            meta_data, raw_data, meta_offset
                        )
                        info.metadata_streams = streams
                        if clr_ver:
                            info.clr_version = clr_ver
                        info.method_count = method_c
                        info.type_count = type_c
                except Exception as e:
                    logger.debug("DotNetAnalyzer: error leyendo metadata header: %s", e)

            # Extraer assembly info desde strings en el binario
            assembly_name, version, culture, pkt = self._extract_assembly_strings(raw_data)
            info.assembly_name = assembly_name
            info.assembly_version = version
            if culture:
                info.culture = culture
            info.public_key_token = pkt

            # Recursos embebidos
            res_count, res_names = self._count_resources(pe)
            info.embedded_resource_count = res_count
            info.embedded_resource_names = res_names[:20]  # Limitar para evitar bloat

        except Exception as e:
            logger.debug("DotNetAnalyzer: _extract_assembly_info error: %s", e)

        return info

    def _parse_clr_flags(self, flags: int) -> List[str]:
        result = []
        if flags & _COMIMAGE_FLAGS_ILONLY:
            result.append("ILONLY")
        if flags & _COMIMAGE_FLAGS_32BITREQUIRED:
            result.append("32BIT_REQUIRED")
        if flags & _COMIMAGE_FLAGS_STRONGNAMESIGNED:
            result.append("STRONG_NAME_SIGNED")
        if flags & _COMIMAGE_FLAGS_NATIVE_ENTRYPOINT:
            result.append("NATIVE_ENTRYPOINT")
        return result

    def _parse_metadata_header(
        self, meta_data: bytes, raw_data: bytes, meta_offset: int
    ):
        """Parsea el BSJB metadata header para obtener streams y versión CLR."""
        streams = []
        clr_ver = ""
        method_count = 0
        type_count = 0

        try:
            # Magic "BSJB"
            if meta_data[:4] != b"BSJB":
                return streams, clr_ver, method_count, type_count

            # Version string length @ offset 12
            ver_len = struct.unpack_from("<I", meta_data, 12)[0]
            if 0 < ver_len <= 128:
                ver_bytes = meta_data[16:16 + ver_len]
                clr_ver = ver_bytes.rstrip(b"\x00").decode("ascii", errors="replace")

            # Stream count @ offset 16+ver_len+2
            base = 16 + ver_len
            # Align to 4 bytes
            base = (base + 3) & ~3
            if base + 4 <= len(meta_data):
                # Skip flags (2 bytes)
                stream_count = struct.unpack_from("<H", meta_data, base + 2)[0]

                # Parse stream headers
                ptr = base + 4
                full_data = raw_data[meta_offset:]
                for _ in range(min(stream_count, 20)):
                    if ptr + 8 >= len(meta_data):
                        break
                    s_offset = struct.unpack_from("<I", meta_data, ptr)[0]
                    s_size = struct.unpack_from("<I", meta_data, ptr + 4)[0]
                    ptr += 8
                    # Stream name (null-terminated, padded to 4 bytes)
                    name_end = meta_data.find(b"\x00", ptr)
                    if name_end == -1:
                        name_end = ptr + 32
                    name = meta_data[ptr:name_end].decode("ascii", errors="replace")
                    streams.append(name)
                    padded = ((name_end - ptr + 1) + 3) & ~3
                    ptr += padded

                    # Contar methods y types desde #~ stream si disponible
                    if name in ("#~", "#-") and s_size > 24:
                        try:
                            tbl_data = full_data[s_offset:s_offset + min(s_size, 4096)]
                            if len(tbl_data) > 24:
                                valid_mask = struct.unpack_from("<Q", tbl_data, 8)[0]
                                # TypeDef = bit 2, MethodDef = bit 6
                                rows_base = 24
                                row_idx = 0
                                for bit in range(64):
                                    if valid_mask & (1 << bit):
                                        if rows_base + (row_idx + 1) * 4 <= len(tbl_data):
                                            row_count = struct.unpack_from(
                                                "<I", tbl_data, rows_base + row_idx * 4
                                            )[0]
                                            if bit == 2:
                                                type_count = row_count
                                            elif bit == 6:
                                                method_count = row_count
                                        row_idx += 1
                        except Exception:
                            pass

        except Exception as e:
            logger.debug("_parse_metadata_header error: %s", e)

        return streams, clr_ver, method_count, type_count


    def _extract_assembly_strings(self, raw_data: bytes):
        """Extrae assembly name, versión, culture y public key token del binario."""
        assembly_name = ""
        version = ""
        culture = ""
        pkt = ""

        try:
            # Buscar patrones de metadata .NET en raw bytes
            # Assembly name: buscar "AssemblyTitleAttribute" o simplemente strings razonables
            # cerca del magic BSJB

            # Public Key Token: patrón de 8 bytes después de "PublicKeyToken="
            pkt_match = re.search(rb"PublicKeyToken=([0-9a-fA-F]{16})", raw_data)
            if pkt_match:
                pkt = pkt_match.group(1).decode("ascii", errors="replace")

            # Version: buscar "Version=X.X.X.X"
            ver_match = re.search(rb"Version=(\d+\.\d+\.\d+\.\d+)", raw_data)
            if ver_match:
                version = ver_match.group(1).decode("ascii", errors="replace")

            # Culture: buscar "Culture=neutral" o similar
            culture_match = re.search(rb"Culture=([a-zA-Z\-]{1,20})", raw_data)
            if culture_match:
                culture = culture_match.group(1).decode("ascii", errors="replace")

            # Assembly name desde strings ASCII
            # Buscamos la primera string ASCII larga que no sea path/system después de BSJB
            bsjb_idx = raw_data.find(b"BSJB")
            if bsjb_idx != -1:
                window = raw_data[bsjb_idx:bsjb_idx + 4096]
                candidates = re.findall(rb"[\x20-\x7E]{4,64}", window)
                for c in candidates:
                    s = c.decode("ascii", errors="replace").strip()
                    # Filtrar rutas y strings del sistema
                    if (
                        len(s) >= 3
                        and not s.startswith("v")
                        and not "\\" in s
                        and not "/" in s
                        and s not in ("BSJB", "neutral", "msil", "amd64")
                        and not s.startswith("System.")
                        and not s.startswith("Microsoft.")
                    ):
                        assembly_name = s
                        break

        except Exception as e:
            logger.debug("_extract_assembly_strings error: %s", e)

        return assembly_name, version, culture, pkt

    def _count_resources(self, pe):
        """Cuenta y lista los recursos embebidos en el PE."""
        count = 0
        names: List[str] = []
        try:
            if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                pe.parse_data_directories(
                    directories=[
                        __import__("pefile").DIRECTORY_ENTRY[
                            "IMAGE_DIRECTORY_ENTRY_RESOURCE"
                        ]
                    ]
                )
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    count += 1
                    if hasattr(entry, "name") and entry.name:
                        names.append(str(entry.name))
                    elif hasattr(entry, "id"):
                        names.append(f"ID_{entry.id}")
        except Exception:
            pass
        return count, names

    # ──────────────────────────────────────────────────────────────────
    # Mejora 3: Detección de ofuscadores
    # ──────────────────────────────────────────────────────────────────

    def _detect_obfuscator(
        self, raw_data: bytes, assembly_info: DotNetAssemblyInfo
    ) -> DotNetObfuscatorInfo:
        """
        Busca firmas de ofuscadores conocidos en los bytes del ensamblado.

        Estrategia multicapa:
            1. String signatures (más confiable)
            2. Metadata anomalies (nombres con caracteres de control)
            3. Resource patterns (recursos con nombres característicos)
        """
        info = DotNetObfuscatorInfo()
        scores: Dict[str, int] = {}

        # 1. String signatures
        for obf_name, sigs in _OBFUSCATOR_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in raw_data.lower():
                    scores[obf_name] = scores.get(obf_name, 0) + 1
                    info.evidence.append(
                        f"{obf_name}: string '{sig.decode('ascii', errors='replace')}'"
                    )

        # 2. Metadata anomalies — nombres de métodos/clases con chars de control
        anomaly_count = 0
        for pattern in _OBFUSCATOR_METADATA_PATTERNS:
            matches = pattern.findall(raw_data)
            anomaly_count += len(matches)

        if anomaly_count > 50:
            info.evidence.append(
                f"metadata_anomaly: {anomaly_count} secuencias de control/unicode raras"
            )
            # Añadir sospecha genérica
            scores["Unknown Obfuscator"] = scores.get("Unknown Obfuscator", 0) + 2

        # 3. Recursos con nombres sospechosos de ofuscadores
        suspicious_res_names = [
            r for r in assembly_info.embedded_resource_names
            if any(
                kw in r.lower()
                for kw in ["confuser", "protect", "obfus", "encrypt", "babel"]
            )
        ]
        for rname in suspicious_res_names:
            info.evidence.append(f"suspicious_resource_name: {rname}")
            scores["Unknown Obfuscator"] = scores.get("Unknown Obfuscator", 0) + 1

        # 4. Detectar ConfuserEx por patrón característico: sección ".text" con alta entropía
        #    + ausencia de debug symbols (heurística adicional, no determinista)
        if not scores:
            # Buscar patrones genéricos de ofuscación por namespace mangling
            null_names = len(re.findall(rb"\x00{3,}", raw_data[:4096]))
            if null_names > 100:
                scores["Generic Obfuscation"] = 1
                info.evidence.append("generic: exceso de secuencias nulas en header area")

        # Elegir el mejor candidato
        if scores:
            best = max(scores, key=lambda k: scores[k])
            best_count = scores[best]
            info.detected = True
            info.name = best
            if best_count >= 3:
                info.confidence = "HIGH"
            elif best_count >= 2:
                info.confidence = "MEDIUM"
            else:
                info.confidence = "LOW"

        return info


    # ──────────────────────────────────────────────────────────────────
    # Mejora 4: Embedded Assemblies Detection
    # ──────────────────────────────────────────────────────────────────

    def _detect_embedded(self, pe, raw_data: bytes) -> DotNetEmbeddedInfo:
        """
        Detecta DLLs embebidas, assemblies comprimidos y PEs en recursos .NET.

        Los loaders .NET modernos (AgentTesla, AsyncRAT) frecuentemente
        almacenan el payload como recurso embebido comprimido o XOR-cifrado.
        """
        info = DotNetEmbeddedInfo()

        try:
            import pefile

            # Parsear recursos si no están parseados
            try:
                pe.parse_data_directories(
                    directories=[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
                    ]
                )
            except Exception:
                pass

            if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                return info

            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if not hasattr(res_type, "directory"):
                    continue
                for res_id in res_type.directory.entries:
                    if not hasattr(res_id, "directory"):
                        continue
                    for res_lang in res_id.directory.entries:
                        try:
                            data_entry = res_lang.data
                            rva = data_entry.struct.OffsetToData
                            size = data_entry.struct.Size

                            if size < _MIN_EMBEDDED_PE_SIZE:
                                continue

                            info.embedded_resources_count += 1
                            res_offset = pe.get_offset_from_rva(rva)
                            if res_offset is None:
                                continue

                            res_bytes = raw_data[res_offset:res_offset + min(size, 1024 * 1024)]

                            # Verificar firma MZ (PE embebido directo)
                            if res_bytes[:2] == _MZ_SIGNATURE:
                                info.embedded_pe_detected = True
                                info.embedded_pe_offsets.append(res_offset)
                                info.embedded_assemblies_count += 1
                                logger.warning(
                                    "DotNetAnalyzer: PE embebido en recurso @ offset %d (size=%d)",
                                    res_offset, size,
                                )
                                continue

                            # Verificar GZIP comprimido (0x1f 0x8b) — payload comprimido
                            if res_bytes[:2] == b"\x1f\x8b":
                                info.compressed_resources += 1
                                # Intentar descomprimir y buscar MZ
                                try:
                                    import zlib
                                    decompressed = zlib.decompress(res_bytes, wbits=47)
                                    if decompressed[:2] == _MZ_SIGNATURE:
                                        info.embedded_pe_detected = True
                                        info.embedded_assemblies_count += 1
                                        logger.warning(
                                            "DotNetAnalyzer: PE embebido GZIP-comprimido @ offset %d",
                                            res_offset,
                                        )
                                except Exception:
                                    pass
                                continue

                            # Verificar DEFLATE / zlib (0x78 0x9c / 0x78 0xda)
                            if res_bytes[:2] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
                                info.compressed_resources += 1
                                try:
                                    import zlib
                                    decompressed = zlib.decompress(res_bytes)
                                    if decompressed[:2] == _MZ_SIGNATURE:
                                        info.embedded_pe_detected = True
                                        info.embedded_assemblies_count += 1
                                except Exception:
                                    pass
                                continue

                            # Buscar MZ oculto en posiciones arbitrarias (XOR-decoded stubs)
                            # Solo escaneamos los primeros 64 bytes buscando MZ potencial
                            for offset in range(0, min(64, len(res_bytes) - 1)):
                                if res_bytes[offset:offset + 2] == _MZ_SIGNATURE:
                                    # Confirmar con signature PE opcional
                                    info.embedded_pe_detected = True
                                    info.embedded_pe_offsets.append(res_offset + offset)
                                    break

                        except Exception as e:
                            logger.debug("DotNetAnalyzer: error analizando recurso: %s", e)

            # Buscar nombres de recursos sospechosos
            info.suspicious_resource_names = self._find_suspicious_resource_names(pe)

        except Exception as e:
            logger.debug("DotNetAnalyzer: _detect_embedded error: %s", e)

        return info

    def _find_suspicious_resource_names(self, pe) -> List[str]:
        """Identifica nombres de recursos sospechosos (payload names)."""
        suspicious: List[str] = []
        suspicious_patterns = [
            "payload", "stub", "dropper", "loader", "inject",
            "crypt", "encrypt", "packed", "binary", "exe",
            "dll", "shellcode", "bot", "rat", "agent",
        ]
        try:
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(entry, "name") and entry.name:
                    name_lower = str(entry.name).lower()
                    if any(p in name_lower for p in suspicious_patterns):
                        suspicious.append(str(entry.name))
        except Exception:
            pass
        return suspicious

    # ──────────────────────────────────────────────────────────────────
    # Mejora 5: Suspicious IL Indicators
    # ──────────────────────────────────────────────────────────────────

    def _detect_suspicious_il(self, raw_data: bytes) -> DotNetSuspiciousILInfo:
        """
        Busca indicadores heurísticos de comportamiento malicioso en strings
        del ensamblado IL (sin descompilar, análisis estático de strings).

        Genera un score IL independiente del modelo ONNX.
        """
        info = DotNetSuspiciousILInfo()
        il_score = 0
        found_strings: List[str] = []

        # Buscar en el binario completo pero limitar a primeros 10 MB
        search_data = raw_data[:10 * 1024 * 1024]

        for pattern in _SUSPICIOUS_IL_PATTERNS:
            if pattern in search_data:
                decoded = pattern.decode("ascii", errors="replace")
                found_strings.append(decoded)

                # Clasificar el indicador
                if b"Reflection" in pattern or b"Assembly.Load" in pattern:
                    info.reflection_usage = True
                    il_score += 8
                elif b"LoadFrom" in pattern or b"LoadFile" in pattern:
                    info.dynamic_loading_detected = True
                    il_score += 15
                elif b"GetManifestResourceStream" in pattern:
                    info.dynamic_loading_detected = True
                    il_score += 12
                elif any(
                    p in pattern
                    for p in [b"VirtualAlloc", b"WriteProcessMemory",
                               b"CreateRemoteThread", b"NtCreateThread"]
                ):
                    if decoded not in info.pinvoke_injection_apis:
                        info.pinvoke_injection_apis.append(decoded)
                    il_score += 20
                elif b"Process.Start" in pattern or b"CreateProcess" in pattern:
                    info.process_spawn_detected = True
                    il_score += 15
                elif b"PowerShell" in pattern or b"Runspace" in pattern:
                    info.powershell_detected = True
                    il_score += 20
                elif any(
                    p in pattern
                    for p in [b"WebClient", b"DownloadString", b"HttpClient"]
                ):
                    info.network_api_detected = True
                    il_score += 10
                elif b"AntiDebug" in pattern or b"IsDebuggerPresent" in pattern:
                    info.antidebug_detected = True
                    il_score += 12
                elif b"GetProcAddress" in pattern or b"LoadLibrary" in pattern:
                    if decoded not in info.pinvoke_injection_apis:
                        info.pinvoke_injection_apis.append(decoded)
                    il_score += 15

        info.suspicious_strings = found_strings[:30]  # Limitar
        info.il_risk_score = min(il_score, 100)

        if found_strings:
            logger.info(
                "DotNetAnalyzer: %d strings IL sospechosas, il_score=%d",
                len(found_strings), info.il_risk_score,
            )

        return info


    # ──────────────────────────────────────────────────────────────────
    # Mejora 6: DotNet Risk Profile
    # ──────────────────────────────────────────────────────────────────

    def _build_risk_profile(
        self,
        assembly_info: DotNetAssemblyInfo,
        obfuscator: DotNetObfuscatorInfo,
        embedded: DotNetEmbeddedInfo,
        suspicious_il: DotNetSuspiciousILInfo,
        raw_data: bytes,
    ) -> DotNetRiskProfile:
        """
        Construye el perfil de riesgo específico para malware .NET.

        Los factores de riesgo se combinan con pesos calibrados para
        distinguir herramientas legítimas protegidas (ConfuserEx empresarial)
        de malware real (.NET RATs, loaders).
        """
        profile = DotNetRiskProfile()
        score = 0
        factors: List[str] = []

        # ── Ofuscación ─────────────────────────────────────────────────
        if obfuscator.detected:
            pts = self._RISK_WEIGHTS["obfuscator_detected"]
            score += pts
            factors.append(
                f"obfuscator={obfuscator.name} confidence={obfuscator.confidence} (+{pts})"
            )

        # Metadata anómala (sin ofuscador identificado = más sospechoso)
        if any("metadata_anomaly" in e for e in obfuscator.evidence) and not obfuscator.detected:
            pts = self._RISK_WEIGHTS["obfuscator_metadata_anomaly"]
            score += pts
            factors.append(f"metadata_anomaly (+{pts})")

        # ── Embedded payloads ──────────────────────────────────────────
        if embedded.embedded_pe_detected:
            pts = self._RISK_WEIGHTS["embedded_pe_in_resources"]
            score += pts
            factors.append(
                f"embedded_pe_in_resources={len(embedded.embedded_pe_offsets)} (+{pts})"
            )

        if embedded.embedded_assemblies_count > 0:
            pts = self._RISK_WEIGHTS["embedded_assembly"]
            score += pts
            factors.append(f"embedded_assemblies={embedded.embedded_assemblies_count} (+{pts})")

        if embedded.compressed_resources > 0:
            pts = self._RISK_WEIGHTS["compressed_resources"]
            score += pts
            factors.append(f"compressed_resources={embedded.compressed_resources} (+{pts})")

        if embedded.suspicious_resource_names:
            pts = self._RISK_WEIGHTS["suspicious_resource_names"]
            score += pts
            factors.append(
                f"suspicious_resource_names={embedded.suspicious_resource_names[:3]} (+{pts})"
            )

        # ── IL Indicators ──────────────────────────────────────────────
        if suspicious_il.reflection_usage:
            pts = self._RISK_WEIGHTS["reflection_usage"]
            score += pts
            factors.append(f"reflection_usage (+{pts})")

        if suspicious_il.dynamic_loading_detected:
            pts = self._RISK_WEIGHTS["dynamic_loading"]
            score += pts
            factors.append(f"dynamic_loading (+{pts})")

        if suspicious_il.pinvoke_injection_apis:
            pts = self._RISK_WEIGHTS["pinvoke_injection"]
            score += pts
            factors.append(
                f"pinvoke_injection={suspicious_il.pinvoke_injection_apis[:3]} (+{pts})"
            )

        if suspicious_il.process_spawn_detected:
            pts = self._RISK_WEIGHTS["process_spawn"]
            score += pts
            factors.append(f"process_spawn (+{pts})")

        if suspicious_il.powershell_detected:
            pts = self._RISK_WEIGHTS["powershell"]
            score += pts
            factors.append(f"powershell_usage (+{pts})")

        if suspicious_il.network_api_detected:
            pts = self._RISK_WEIGHTS["network_apis"]
            score += pts
            factors.append(f"network_apis (+{pts})")

        if suspicious_il.antidebug_detected:
            pts = self._RISK_WEIGHTS["antidebug"]
            score += pts
            factors.append(f"antidebug_detected (+{pts})")

        # ── Clasificación final ────────────────────────────────────────
        profile.dotnet_risk_score = min(score, 999)
        profile.dotnet_risk_level = self._classify_dotnet_risk(score)
        profile.risk_factors = factors

        logger.info(
            "DotNetAnalyzer: dotnet_risk_score=%d level=%s factors=%d",
            score, profile.dotnet_risk_level, len(factors),
        )

        return profile

    def _classify_dotnet_risk(self, score: int) -> str:
        for level, (low, high) in self._RISK_THRESHOLDS.items():
            if low <= score <= high:
                return level
        return "CRITICAL"

