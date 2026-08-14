"""
core/dotnet/il_analyzer.py — IL Behavioral Analyzer con trazabilidad forense completa.

AUDITORÍA DE ARQUITECTURA:
    Versión anterior: búsqueda plana de bytes en el binario completo.
    Problema: no distinguía la fuente CLR — un string podría estar en el
    código del analizador embebido, en comentarios, en recursos no ejecutables,
    o en la sección de datos, sin que eso implique comportamiento real.

    Esta versión extrae PRIMERO las tablas CLR reales (Fase 1 — ClrStreams),
    luego busca indicadores ÚNICAMENTE dentro de los tokens extraídos.

    Fuentes verificadas (en orden de confianza decreciente):
        1. MemberRef table  → llamadas a métodos externos (más alta confianza)
        2. TypeRef table    → tipos referenciados por AssemblyRef
        3. AssemblyRef      → assemblies importados (System.Net, etc.)
        4. #Strings heap    → nombres de TypeDef/MethodDef propios
        5. #US heap         → user strings literales en IL (ldstr opcode)
        6. P/Invoke (ImplMap + ModuleRef) → llamadas nativas directas

    Cada Evidence tiene:
        source      : "MemberRef" / "TypeRef" / "AssemblyRef" / "PInvoke" /
                      "UserString" / "StringsHeap"
        value       : string exacto encontrado
        location    : "MemberRef #N" / "TypeRef #N" / offset hex
        confidence  : "high" / "medium" / "low"

Compatibilidad:
    - NO modifica el vector de 2381 features.
    - NO modifica la inferencia ONNX, el scaler, ni el modelo.
    - Fase 6 del pipeline existente en engine.py — mismo scan_file().
"""
from __future__ import annotations

import math
import re
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import setup_logger

logger = setup_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Estructuras de evidencia forense
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Evidence:
    """
    Unidad mínima de evidencia forense.

    source     : tabla CLR o stream donde se encontró el valor.
    value      : string exacto hallado en el binario.
    location   : identificador preciso (tabla + índice o offset).
    confidence : "high" si proviene de MemberRef/PInvoke/AssemblyRef,
                 "medium" si de TypeRef/#Strings,
                 "low" si de #US o búsqueda fallback.
    """
    source: str
    value: str
    location: str
    confidence: str   # "high" / "medium" / "low"

    def to_dict(self) -> dict:
        return {
            "source":     self.source,
            "value":      self.value,
            "location":   self.location,
            "confidence": self.confidence,
        }


@dataclass
class BehaviorIndicator:
    """Indicador de comportamiento con evidencia trazable completa."""
    detected: bool = False
    score: int = 0
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self, prefix: str = "") -> dict:
        return {
            f"{prefix}detected":       self.detected,
            f"{prefix}score":          self.score,
            f"{prefix}evidence_count": len(self.evidence),
            f"{prefix}evidence":       [e.to_dict() for e in self.evidence],
        }


# ─────────────────────────────────────────────────────────────────────────────
# ClrStreamExtractor — Extrae tokens de las tablas CLR reales
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ClrTokens:
    """
    Colección de tokens extraídos directamente de las tablas CLR.
    Cada lista contiene tuplas (valor_string, fuente_legible, índice).
    """
    member_refs:   List[Tuple[str, str, int]] = field(default_factory=list)
    type_refs:     List[Tuple[str, str, int]] = field(default_factory=list)
    assembly_refs: List[Tuple[str, str, int]] = field(default_factory=list)
    pinvoke_refs:  List[Tuple[str, str, int]] = field(default_factory=list)
    user_strings:  List[Tuple[str, str, int]] = field(default_factory=list)
    strings_heap:  List[Tuple[str, str, int]] = field(default_factory=list)


class ClrStreamExtractor:
    """
    Extrae los streams CLR de un ensamblado .NET directamente de los bytes.

    Proceso:
        1. Localiza la metadata signature BSJB en los bytes del PE.
        2. Parsea el BSJB header para obtener los offsets de cada stream.
        3. Extrae los strings del #Strings heap.
        4. Extrae los user strings del #US heap.
        5. Parsea la tabla #~ (MethodSpec/MemberRef/TypeRef/AssemblyRef/ImplMap).
    """

    def extract(self, raw_data: bytes, pe_obj=None) -> Optional[ClrTokens]:
        """
        Retorna ClrTokens con todos los tokens CLR extraídos.
        Retorna None si no se puede localizar la metadata.
        """
        tokens = ClrTokens()

        # ── Paso 1: localizar BSJB ────────────────────────────────────
        bsjb_off = raw_data.find(b"BSJB")
        if bsjb_off == -1:
            return None

        meta_data = raw_data[bsjb_off:]

        # ── Paso 2: parsear BSJB header para obtener stream offsets ───
        try:
            stream_offsets = self._parse_bsjb_streams(meta_data)
        except Exception as e:
            logger.debug("ClrStreamExtractor: error parseando BSJB: %s", e)
            return None

        if not stream_offsets:
            return tokens

        # ── Paso 3: #Strings heap ──────────────────────────────────────
        if "#Strings" in stream_offsets:
            off, sz = stream_offsets["#Strings"]
            self._extract_strings_heap(
                meta_data[off:off + sz], tokens
            )

        # ── Paso 4: #US heap (User Strings) ───────────────────────────
        if "#US" in stream_offsets:
            off, sz = stream_offsets["#US"]
            self._extract_us_heap(
                meta_data[off:off + sz], tokens
            )

        # ── Paso 5: #~ / #- tables ────────────────────────────────────
        table_stream = stream_offsets.get("#~") or stream_offsets.get("#-")
        strings_off = stream_offsets.get("#Strings", (0, 0))[0]
        if table_stream:
            off, sz = table_stream
            self._parse_tables(
                meta_data[off:off + sz],
                meta_data[strings_off:],
                tokens,
            )

        return tokens

    # ── BSJB stream header parser ──────────────────────────────────────

    def _parse_bsjb_streams(self, meta: bytes) -> Dict[str, Tuple[int, int]]:
        """
        Parsea el BSJB metadata header y devuelve {name: (offset, size)}.
        offset es relativo al inicio del bloque meta (BSJB).
        """
        result: Dict[str, Tuple[int, int]] = {}
        if len(meta) < 20:
            return result

        # Magic "BSJB" @ 0
        if meta[:4] != b"BSJB":
            return result

        # Version string length @ 12
        ver_len = struct.unpack_from("<I", meta, 12)[0]
        if ver_len > 256:
            return result

        # Flags @ 16 + ver_len (aligned to 4)
        base = 16 + ver_len
        base = (base + 3) & ~3

        if base + 4 > len(meta):
            return result

        # NumberOfStreams @ base + 2
        num_streams = struct.unpack_from("<H", meta, base + 2)[0]
        if num_streams > 32:
            return result

        ptr = base + 4
        for _ in range(num_streams):
            if ptr + 8 > len(meta):
                break
            stream_off = struct.unpack_from("<I", meta, ptr)[0]
            stream_sz  = struct.unpack_from("<I", meta, ptr + 4)[0]
            ptr += 8

            # Stream name: null-terminated, aligned to 4 bytes
            name_end = meta.find(b"\x00", ptr)
            if name_end == -1 or name_end - ptr > 32:
                break
            name = meta[ptr:name_end].decode("ascii", errors="replace")
            padded = ((name_end - ptr + 1) + 3) & ~3
            ptr += padded

            result[name] = (stream_off, stream_sz)

        return result

    # ── #Strings heap ──────────────────────────────────────────────────

    def _extract_strings_heap(self, data: bytes, tokens: ClrTokens) -> None:
        """
        Extrae todos los strings del #Strings heap (null-separated).
        Estos son nombres de TypeDef, MethodDef, Field, etc.
        """
        idx = 0
        entry_num = 0
        while idx < len(data):
            end = data.find(b"\x00", idx)
            if end == -1:
                end = len(data)
            chunk = data[idx:end]
            if len(chunk) >= 3:
                try:
                    s = chunk.decode("utf-8", errors="replace")
                    tokens.strings_heap.append(
                        (s, "StringsHeap", idx)
                    )
                except Exception:
                    pass
            idx = end + 1
            entry_num += 1
            if entry_num > 50000:   # safety cap
                break

    # ── #US heap ───────────────────────────────────────────────────────

    def _extract_us_heap(self, data: bytes, tokens: ClrTokens) -> None:
        """
        Extrae user strings del #US heap.
        Formato: blob length (compressed uint) + UTF-16LE string + 1 terminal byte.
        """
        idx = 1   # El primer byte es siempre 0 (empty string)
        entry_num = 0
        while idx < len(data) - 1:
            # Leer compressed length
            b0 = data[idx]
            if b0 == 0:
                idx += 1
                continue
            if b0 & 0xC0 == 0xC0:
                if idx + 3 >= len(data):
                    break
                length = ((b0 & 0x1F) << 24 | data[idx+1] << 16 |
                          data[idx+2] << 8 | data[idx+3])
                idx += 4
            elif b0 & 0x80 == 0x80:
                if idx + 1 >= len(data):
                    break
                length = ((b0 & 0x3F) << 8) | data[idx + 1]
                idx += 2
            else:
                length = b0 & 0x7F
                idx += 1

            if length <= 0 or idx + length > len(data):
                idx += 1
                continue

            blob = data[idx:idx + length - 1]   # -1 para ignorar terminal byte
            try:
                s = blob.decode("utf-16-le", errors="replace")
                if len(s) >= 3 and any(c.isprintable() for c in s[:8]):
                    tokens.user_strings.append(
                        (s, "UserString", idx)
                    )
            except Exception:
                pass

            idx += length
            entry_num += 1
            if entry_num > 20000:
                break

    # ── #~ table parser (parcial — MemberRef, TypeRef, AssemblyRef) ───

    def _parse_tables(
        self,
        table_data: bytes,
        strings_data: bytes,
        tokens: ClrTokens,
    ) -> None:
        """
        Parsea las tablas del #~ stream para extraer:
            - AssemblyRef (tabla 0x23): nombres de assemblies importados.
            - TypeRef (tabla 0x01): tipos externos referenciados.
            - MemberRef (tabla 0x0A): métodos/fields externos.
            - ImplMap (tabla 0x1C): P/Invoke entries.
            - ModuleRef (tabla 0x1A): DLLs referenciadas por P/Invoke.

        Implementación parcial: parsea el header para obtener row counts,
        luego extrae los string heap indices de cada fila relevante.
        """
        if len(table_data) < 24:
            return

        try:
            # Table header
            # reserved (4), MajorVersion, MinorVersion, HeapSizes (1), Reserved2 (1)
            heap_sizes = table_data[6]
            string_index_size = 4 if (heap_sizes & 0x01) else 2
            guid_index_size   = 4 if (heap_sizes & 0x02) else 4
            blob_index_size   = 4 if (heap_sizes & 0x04) else 2

            # Valid tables bitmask @ offset 8
            if len(table_data) < 16:
                return
            valid_mask = struct.unpack_from("<Q", table_data, 8)[0]

            # Row counts array starts at offset 24
            # Count one DWORD per bit set in valid_mask
            row_counts: Dict[int, int] = {}
            rc_ptr = 24
            for bit in range(64):
                if valid_mask & (1 << bit):
                    if rc_ptr + 4 > len(table_data):
                        break
                    count = struct.unpack_from("<I", table_data, rc_ptr)[0]
                    row_counts[bit] = count
                    rc_ptr += 4

            # Now parse relevant tables
            # Calculate row sizes and offsets
            self._parse_assemblyref(
                table_data, rc_ptr, row_counts,
                string_index_size, blob_index_size,
                strings_data, tokens,
            )
            self._parse_typeref(
                table_data, rc_ptr, row_counts,
                string_index_size,
                strings_data, tokens,
            )
            self._parse_memberref(
                table_data, rc_ptr, row_counts,
                string_index_size, blob_index_size,
                strings_data, tokens,
            )
            self._parse_moduleref(
                table_data, rc_ptr, row_counts,
                string_index_size,
                strings_data, tokens,
            )

        except Exception as e:
            logger.debug("_parse_tables error: %s", e)

    def _read_string_index(self, data: bytes, offset: int, size: int) -> int:
        if size == 2 and offset + 2 <= len(data):
            return struct.unpack_from("<H", data, offset)[0]
        if offset + 4 <= len(data):
            return struct.unpack_from("<I", data, offset)[0]
        return 0

    def _get_string(self, strings_data: bytes, index: int) -> str:
        if index == 0 or index >= len(strings_data):
            return ""
        end = strings_data.find(b"\x00", index)
        if end == -1:
            end = min(index + 256, len(strings_data))
        try:
            return strings_data[index:end].decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _compute_table_offset(
        self,
        table_data: bytes,
        tables_base: int,
        row_counts: Dict[int, int],
        target_table: int,
        string_sz: int,
        blob_sz: int,
    ) -> Tuple[int, int]:
        """
        Calcula el offset y el row_count de una tabla en el stream.
        Devuelve (offset_desde_inicio_data, row_count).

        Tamaños de fila por tabla (simplificado para las tablas que nos interesan).
        Para tablas que no conocemos el tamaño, hacemos fallback a 0.
        """
        # Tamaños fijos conocidos de cada tabla CLR (indexados por table_id)
        # Formato: lista de columnas (type_code, size)
        # type_code: 's'=string_index, 'b'=blob_index, 'g'=guid_index,
        #            'r2'=ResolutionScope coded 2B, 'r4'=4B, 'u2'=uint16, 'u4'=uint32
        TABLE_ROW_SIZE: Dict[int, int] = {
            0x00: 2 + string_sz + string_sz,                    # Module
            0x01: 2 + string_sz + string_sz,                    # TypeRef (ResolutionScope + Name + Namespace)
            0x02: 4 + string_sz + string_sz + 2 + 2 + 2 + 2 + 2 + 2,  # TypeDef
            0x04: 2 + string_sz + blob_sz,                      # Field
            0x06: 4 + string_sz + blob_sz,                      # MethodDef
            0x08: 4 + string_sz,                                # Param
            0x0A: 2 + string_sz + blob_sz,                      # MemberRef (class + name + sig)
            0x1A: string_sz,                                     # ModuleRef
            0x1C: 2 + 2 + 2,                                    # ImplMap
            0x23: 8 + blob_sz + string_sz + string_sz + blob_sz, # AssemblyRef
        }

        offset = tables_base
        for table_id in sorted(row_counts.keys()):
            if table_id == target_table:
                row_count = row_counts.get(target_table, 0)
                return offset, row_count
            row_sz = TABLE_ROW_SIZE.get(table_id, 0)
            n_rows = row_counts.get(table_id, 0)
            offset += row_sz * n_rows

        return 0, 0

    def _parse_assemblyref(
        self, table_data, tables_base, row_counts,
        str_sz, blob_sz, strings_data, tokens
    ):
        """AssemblyRef (0x23): extrae nombres de assemblies referenciados."""
        off, count = self._compute_table_offset(
            table_data, tables_base, row_counts, 0x23, str_sz, blob_sz
        )
        if count == 0 or off == 0:
            return

        # Row: u2 MajorV + u2 MinorV + u2 BuildN + u2 RevisionN +
        #      u4 Flags + blob PublicKeyOrToken +
        #      string Name + string Culture + blob HashValue
        row_sz = 8 + blob_sz + str_sz + str_sz + blob_sz
        for i in range(min(count, 200)):
            row_off = off + i * row_sz
            if row_off + row_sz > len(table_data):
                break
            # Name is at offset 8 + blob_sz within the row
            name_idx_off = row_off + 8 + blob_sz
            name_idx = self._read_string_index(table_data, name_idx_off, str_sz)
            name = self._get_string(strings_data, name_idx)
            if name:
                tokens.assembly_refs.append(
                    (name, "AssemblyRef", i + 1)
                )

    def _parse_typeref(
        self, table_data, tables_base, row_counts,
        str_sz, strings_data, tokens
    ):
        """TypeRef (0x01): extrae tipos externos referenciados."""
        # ResolutionScope is a coded index: 2 or 4 bytes
        # For simplicity we use 2-byte coded index (sufficient for most assemblies)
        coded_sz = 2
        off, count = self._compute_table_offset(
            table_data, tables_base, row_counts, 0x01, str_sz, 2
        )
        if count == 0 or off == 0:
            return

        row_sz = coded_sz + str_sz + str_sz
        for i in range(min(count, 2000)):
            row_off = off + i * row_sz
            if row_off + row_sz > len(table_data):
                break
            name_idx   = self._read_string_index(table_data, row_off + coded_sz, str_sz)
            ns_idx     = self._read_string_index(table_data, row_off + coded_sz + str_sz, str_sz)
            name       = self._get_string(strings_data, name_idx)
            namespace  = self._get_string(strings_data, ns_idx)
            full_name  = f"{namespace}.{name}" if namespace else name
            if full_name and len(full_name) >= 3:
                tokens.type_refs.append(
                    (full_name, "TypeRef", i + 1)
                )

    def _parse_memberref(
        self, table_data, tables_base, row_counts,
        str_sz, blob_sz, strings_data, tokens
    ):
        """MemberRef (0x0A): extrae referencias a métodos y fields externos."""
        coded_sz = 2   # MemberRefParent coded index
        off, count = self._compute_table_offset(
            table_data, tables_base, row_counts, 0x0A, str_sz, blob_sz
        )
        if count == 0 or off == 0:
            return

        row_sz = coded_sz + str_sz + blob_sz
        for i in range(min(count, 5000)):
            row_off = off + i * row_sz
            if row_off + row_sz > len(table_data):
                break
            name_idx = self._read_string_index(table_data, row_off + coded_sz, str_sz)
            name     = self._get_string(strings_data, name_idx)
            if name and len(name) >= 2:
                tokens.member_refs.append(
                    (name, "MemberRef", i + 1)
                )

    def _parse_moduleref(
        self, table_data, tables_base, row_counts,
        str_sz, strings_data, tokens
    ):
        """ModuleRef (0x1A): DLLs importadas por P/Invoke."""
        off, count = self._compute_table_offset(
            table_data, tables_base, row_counts, 0x1A, str_sz, 2
        )
        if count == 0 or off == 0:
            return

        row_sz = str_sz
        for i in range(min(count, 500)):
            row_off = off + i * row_sz
            if row_off + row_sz > len(table_data):
                break
            name_idx = self._read_string_index(table_data, row_off, str_sz)
            name     = self._get_string(strings_data, name_idx)
            if name:
                tokens.pinvoke_refs.append(
                    (name, "ModuleRef/PInvoke", i + 1)
                )



# ─────────────────────────────────────────────────────────────────────────────
# CATÁLOGOS DE INDICADORES
# Cada entrada: (pattern, description, source_priority, confidence)
# source_priority: qué tablas CLR son relevantes para este indicador
# ─────────────────────────────────────────────────────────────────────────────

# Confianza por fuente CLR
_SOURCE_CONFIDENCE: Dict[str, str] = {
    "MemberRef":          "high",
    "ModuleRef/PInvoke":  "high",
    "AssemblyRef":        "high",
    "TypeRef":            "medium",
    "StringsHeap":        "medium",
    "UserString":         "medium",
    "Fallback":           "low",
}

# Tupla: (pattern_lower, descripción, fuentes_aceptadas)
# fuentes_aceptadas: qué fuentes CLR pueden confirmar este indicador
_M2_REFLECTION = [
    ("assembly",            "Assembly class ref",    ["MemberRef","TypeRef","AssemblyRef","StringsHeap"]),
    ("activator",           "Activator class ref",   ["MemberRef","TypeRef","StringsHeap"]),
    ("methodinfo",          "MethodInfo ref",        ["MemberRef","TypeRef","StringsHeap"]),
    ("type.gettype",        "Type.GetType",          ["MemberRef","StringsHeap","UserString"]),
    ("invokemember",        "InvokeMember",          ["MemberRef","StringsHeap"]),
    ("dynamicmethod",       "DynamicMethod",         ["MemberRef","TypeRef","StringsHeap"]),
    ("system.reflection",   "System.Reflection ns",  ["AssemblyRef","TypeRef","StringsHeap"]),
    ("getmethod",           "GetMethod reflection",  ["MemberRef","StringsHeap"]),
    ("ilgenerator",         "ILGenerator emit",      ["MemberRef","TypeRef","StringsHeap"]),
]

_M3_DYNAMIC_LOADING = [
    ("assembly.load",           "Assembly.Load(bytes)",    ["MemberRef","StringsHeap"]),
    ("loadfrom",                "Assembly.LoadFrom",       ["MemberRef","StringsHeap","UserString"]),
    ("loadfile",                "Assembly.LoadFile",       ["MemberRef","StringsHeap","UserString"]),
    ("getmanifestresourcestream","Resource→Load",          ["MemberRef","StringsHeap"]),
    ("binaryformatter",         "BinaryFormatter deser",   ["TypeRef","StringsHeap","MemberRef"]),
    ("resourcemanager",         "ResourceManager load",    ["TypeRef","StringsHeap","MemberRef"]),
    ("objectstateformatter",    "ObjectStateFormatter",    ["TypeRef","StringsHeap"]),
    ("xmlserializer",           "XmlSerializer deser",     ["TypeRef","StringsHeap","MemberRef"]),
]

_M5_INJECTION = [
    ("virtualalloc",            "VirtualAlloc",            ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("virtualallocex",          "VirtualAllocEx",          ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("writeprocessmemory",      "WriteProcessMemory",      ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("ntwritevirtualmemory",    "NtWriteVirtualMemory",    ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("createremotethread",      "CreateRemoteThread",      ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("queueuserapc",            "QueueUserAPC",            ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("ntqueueapcthread",        "NtQueueApcThread",        ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("setthreadcontext",        "SetThreadContext",         ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("resumethread",            "ResumeThread",            ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("ntunmapviewofsection",    "NtUnmapViewOfSection",    ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("zwunmapviewofsection",    "ZwUnmapViewOfSection",    ["MemberRef","ModuleRef/PInvoke","StringsHeap","UserString"]),
    ("marshal.getdelegatefor",  "Marshal FuncPtr DynPInvoke",["MemberRef","StringsHeap"]),
    ("allochglobal",            "Marshal.AllocHGlobal",    ["MemberRef","StringsHeap"]),
    ("marshal.copy",            "Marshal.Copy shellcode",  ["MemberRef","StringsHeap"]),
]

_M6_PERSISTENCE = [
    ("currentversion\\run",     "Registry Run key",        ["UserString","StringsHeap"]),
    ("currentversion\\runonce", "Registry RunOnce key",    ["UserString","StringsHeap"]),
    ("scheduledtask",           "ScheduledTask COM",       ["TypeRef","StringsHeap","MemberRef"]),
    ("schtasks",                "schtasks.exe spawn",      ["UserString","StringsHeap"]),
    ("taskservice",             "ITaskService COM",        ["TypeRef","StringsHeap","MemberRef"]),
    ("shell:startup",           "Startup folder path",     ["UserString","StringsHeap"]),
    ("servicebase",             "Service installation",    ["TypeRef","StringsHeap","MemberRef"]),
    ("managementobject",        "WMI ManagementObject",    ["TypeRef","StringsHeap","MemberRef"]),
    ("__eventfilter",           "WMI EventFilter persist", ["UserString","StringsHeap"]),
    ("instancecreationevent",   "WMI subscription",        ["UserString","StringsHeap"]),
]

_M7_NETWORKING = [
    ("system.net.sockets",      "System.Net.Sockets ns",  ["AssemblyRef","TypeRef","StringsHeap"]),
    ("system.net.http",         "System.Net.Http ns",     ["AssemblyRef","TypeRef","StringsHeap"]),
    ("tcpclient",               "TcpClient",              ["TypeRef","MemberRef","StringsHeap"]),
    ("udpclient",               "UdpClient",              ["TypeRef","MemberRef","StringsHeap"]),
    ("httpclient",              "HttpClient",             ["TypeRef","MemberRef","StringsHeap"]),
    ("httpwebrequest",          "HttpWebRequest",         ["TypeRef","MemberRef","StringsHeap"]),
    ("webclient",               "WebClient",              ["TypeRef","MemberRef","StringsHeap"]),
    ("downloadstring",          "DownloadString",         ["MemberRef","StringsHeap"]),
    ("downloadfile",            "DownloadFile",           ["MemberRef","StringsHeap"]),
    ("downloaddata",            "DownloadData",           ["MemberRef","StringsHeap"]),
    ("networkstream",           "NetworkStream raw TCP",  ["TypeRef","MemberRef","StringsHeap"]),
    ("dns.gethostentry",        "DNS resolution",         ["MemberRef","StringsHeap"]),
    ("smtpclient",              "SmtpClient email exfil", ["TypeRef","MemberRef","StringsHeap"]),
    ("ftpwebrequest",           "FTP exfiltration",       ["TypeRef","MemberRef","StringsHeap"]),
    ("socket",                  "Socket raw",             ["TypeRef","MemberRef","StringsHeap"]),
    ("webproxy",                "WebProxy C2 pivot",      ["TypeRef","MemberRef","StringsHeap"]),
    ("uploaddata",              "WebClient.UploadData",   ["MemberRef","StringsHeap"]),
    ("uploadstring",            "WebClient.UploadString", ["MemberRef","StringsHeap"]),
]

_M8_CMD_EXEC = [
    ("cmd.exe",             "cmd.exe spawn",              ["UserString","StringsHeap"]),
    ("powershell.exe",      "powershell.exe spawn",       ["UserString","StringsHeap"]),
    ("pwsh.exe",            "pwsh.exe spawn",             ["UserString","StringsHeap"]),
    ("wscript.exe",         "wscript.exe",                ["UserString","StringsHeap"]),
    ("cscript.exe",         "cscript.exe",                ["UserString","StringsHeap"]),
    ("rundll32.exe",        "rundll32.exe",               ["UserString","StringsHeap"]),
    ("regsvr32.exe",        "regsvr32.exe squiblydoo",    ["UserString","StringsHeap"]),
    ("mshta.exe",           "mshta.exe",                  ["UserString","StringsHeap"]),
    ("certutil.exe",        "certutil LOLBin",            ["UserString","StringsHeap"]),
    ("process.start",       "Process.Start",              ["MemberRef","StringsHeap"]),
    ("processstartinfo",    "ProcessStartInfo",           ["TypeRef","StringsHeap","MemberRef"]),
    ("shellexecute",        "ShellExecute",               ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("createprocess",       "CreateProcess",              ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("redirectstandardoutput","stdout redirect",          ["MemberRef","StringsHeap"]),
    ("-encodedcommand",     "PS EncodedCommand",          ["UserString","StringsHeap"]),
    ("invoke-expression",   "IEX",                        ["UserString","StringsHeap"]),
]

_M9_CREDENTIAL = [
    ("login data",          "Chrome Login Data",          ["UserString","StringsHeap"]),
    ("local state",         "Chrome Local State key",     ["UserString","StringsHeap"]),
    ("chrome\\user data",   "Chrome profile path",        ["UserString","StringsHeap"]),
    ("edge\\user data",     "Edge profile path",          ["UserString","StringsHeap"]),
    ("logins.json",         "Firefox logins.json",        ["UserString","StringsHeap"]),
    ("key4.db",             "Firefox NSS key DB",         ["UserString","StringsHeap"]),
    ("firefox\\profiles",   "Firefox profiles path",      ["UserString","StringsHeap"]),
    ("cryptunprotectdata",  "DPAPI CryptUnprotect",       ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("protecteddata",       "ProtectedData.Unprotect",    ["TypeRef","MemberRef","StringsHeap"]),
    ("credread",            "CredRead CredMan API",        ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("credenumerate",       "CredEnumerate",              ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("thunderbird",         "Thunderbird creds",          ["UserString","StringsHeap"]),
]

_M10_WORM = [
    ("driveinfo.getdrives", "DriveInfo.GetDrives USB",    ["MemberRef","StringsHeap"]),
    ("drivetype.removable", "Removable drive check",      ["StringsHeap","UserString"]),
    ("autorun.inf",         "autorun.inf creation",       ["UserString","StringsHeap"]),
    ("recycler",            "RECYCLER folder hiding",     ["UserString","StringsHeap"]),
    ("netshareenum",        "NetShareEnum P/Invoke",      ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("wnetenumresource",    "WNetEnumResource shares",    ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("getlogicaldrives",    "GetLogicalDrives",           ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("file.copy",           "File.Copy replication",      ["MemberRef","StringsHeap"]),
    ("file.writeallbytes",  "File.WriteAllBytes drop",    ["MemberRef","StringsHeap"]),
    ("smb",                 "SMB reference",              ["UserString","StringsHeap"]),
]

_M11_STEALER = [
    ("discord",             "Discord reference",          ["UserString","StringsHeap"]),
    ("discordapp.com",      "Discord API endpoint",       ["UserString","StringsHeap"]),
    ("discord\\local storage","Discord token path",       ["UserString","StringsHeap"]),
    ("api.telegram.org",    "Telegram Bot API",           ["UserString","StringsHeap"]),
    ("sendmessage",         "Telegram sendMessage",       ["MemberRef","UserString","StringsHeap"]),
    ("senddocument",        "Telegram sendDocument exfil",["UserString","StringsHeap"]),
    ("clipboard.gettext",   "Clipboard.GetText",          ["MemberRef","StringsHeap"]),
    ("getclipboarddata",    "GetClipboardData Win32",     ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("exodus\\exodus.wallet","Exodus wallet path",        ["UserString","StringsHeap"]),
    ("electrum\\wallets",   "Electrum wallet path",       ["UserString","StringsHeap"]),
    ("wallet.dat",          "Bitcoin wallet.dat",         ["UserString","StringsHeap"]),
    ("metamask",            "MetaMask extension",         ["UserString","StringsHeap"]),
    ("copyfromscreen",      "Screen capture",             ["MemberRef","StringsHeap"]),
    ("bitblt",              "BitBlt screen grab",         ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
]

_M12_RAT = [
    ("standardinput",       "Shell stdin redirect",       ["MemberRef","StringsHeap"]),
    ("standardoutput",      "Shell stdout redirect",      ["MemberRef","StringsHeap"]),
    ("standarderror",       "Shell stderr redirect",      ["MemberRef","StringsHeap"]),
    ("copyfromscreen",      "Screen capture",             ["MemberRef","StringsHeap"]),
    ("getdesktopwindow",    "Desktop capture",            ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("getasynckeystate",    "Keylogger GetAsyncKeyState", ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("setwindowshookex",    "Hook keylogger",             ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("wh_keyboard_ll",      "Low-level keyboard hook",    ["StringsHeap","UserString"]),
    ("getkeystate",         "GetKeyState",                ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("aforge",              "AForge.NET webcam lib",      ["AssemblyRef","TypeRef","StringsHeap"]),
    ("wavein",              "WaveIn microphone",          ["StringsHeap","UserString"]),
    ("waveinopen",          "waveInOpen record",          ["MemberRef","ModuleRef/PInvoke","StringsHeap"]),
    ("file.delete",         "Remote file delete",         ["MemberRef","StringsHeap"]),
    ("directory.getfiles",  "Remote file listing",        ["MemberRef","StringsHeap"]),
    ("registry.setvalue",   "Remote registry write",      ["MemberRef","StringsHeap"]),
]

# Family scoring matrix (unchanged from previous version)
_FAMILY_WEIGHTS: Dict[str, Dict[str, int]] = {
    "reflection":       {"xworm": 8,  "asyncrat": 12, "agenttesla": 5,  "njrat": 8,  "quasarrat": 10, "formbook": 3},
    "dynamic_loading":  {"xworm": 10, "asyncrat": 15, "agenttesla": 8,  "njrat": 5,  "quasarrat": 8,  "formbook": 5},
    "injection":        {"xworm": 15, "asyncrat": 10, "agenttesla": 5,  "njrat": 10, "quasarrat": 8,  "formbook": 12},
    "persistence":      {"xworm": 15, "asyncrat": 12, "agenttesla": 10, "njrat": 15, "quasarrat": 10, "formbook": 8},
    "networking":       {"xworm": 18, "asyncrat": 18, "agenttesla": 15, "njrat": 15, "quasarrat": 15, "formbook": 12},
    "cmd_exec":         {"xworm": 12, "asyncrat": 8,  "agenttesla": 5,  "njrat": 10, "quasarrat": 6,  "formbook": 8},
    "credential_theft": {"xworm": 5,  "asyncrat": 5,  "agenttesla": 20, "njrat": 5,  "quasarrat": 5,  "formbook": 15},
    "worm":             {"xworm": 20, "asyncrat": 3,  "agenttesla": 2,  "njrat": 8,  "quasarrat": 2,  "formbook": 2},
    "stealer":          {"xworm": 8,  "asyncrat": 5,  "agenttesla": 18, "njrat": 3,  "quasarrat": 3,  "formbook": 15},
    "rat":              {"xworm": 15, "asyncrat": 18, "agenttesla": 8,  "njrat": 18, "quasarrat": 20, "formbook": 5},
}
_FAMILY_MAX: Dict[str, int] = {
    fam: sum(v.get(fam, 0) for v in _FAMILY_WEIGHTS.values())
    for fam in ["xworm", "asyncrat", "agenttesla", "njrat", "quasarrat", "formbook"]
}



# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses de resultado (idénticos a versión anterior para compatibilidad)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ILBehavioralReport:
    reflection:         BehaviorIndicator = field(default_factory=BehaviorIndicator)
    dynamic_loading:    BehaviorIndicator = field(default_factory=BehaviorIndicator)
    embedded_resources: BehaviorIndicator = field(default_factory=BehaviorIndicator)
    resource_count:     int = 0
    embedded_pe_count:  int = 0
    embedded_assembly_count: int = 0
    encrypted_resource_count: int = 0
    resource_entropy_avg: float = 0.0
    injection:          BehaviorIndicator = field(default_factory=BehaviorIndicator)
    persistence:        BehaviorIndicator = field(default_factory=BehaviorIndicator)
    networking:         BehaviorIndicator = field(default_factory=BehaviorIndicator)
    cmd_exec:           BehaviorIndicator = field(default_factory=BehaviorIndicator)
    credential_theft:   BehaviorIndicator = field(default_factory=BehaviorIndicator)
    worm:               BehaviorIndicator = field(default_factory=BehaviorIndicator)
    stealer:            BehaviorIndicator = field(default_factory=BehaviorIndicator)
    rat:                BehaviorIndicator = field(default_factory=BehaviorIndicator)
    family_likelihoods: Dict[str, int] = field(default_factory=dict)
    top_family:         str = ""
    dotnet_threat_score: int = 0
    dotnet_threat_level: str = "LOW"
    all_evidence:       List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializa con evidencia completa (Fase 2 del spec forense)."""
        d: Dict[str, Any] = {
            "reflection_detected":         self.reflection.detected,
            "reflection_score":            self.reflection.score,
            "reflection_evidence":         [e.to_dict() for e in self.reflection.evidence],
            "dynamic_loading_detected":    self.dynamic_loading.detected,
            "dynamic_loading_score":       self.dynamic_loading.score,
            "dynamic_loading_evidence":    [e.to_dict() for e in self.dynamic_loading.evidence],
            "embedded_resource_count":     self.resource_count,
            "embedded_pe_count":           self.embedded_pe_count,
            "embedded_assembly_count":     self.embedded_assembly_count,
            "encrypted_resource_count":    self.encrypted_resource_count,
            "resource_entropy_avg":        round(self.resource_entropy_avg, 4),
            "injection_detected":          self.injection.detected,
            "injection_score":             self.injection.score,
            "injection_evidence":          [e.to_dict() for e in self.injection.evidence],
            "persistence_detected":        self.persistence.detected,
            "persistence_score":           self.persistence.score,
            "persistence_evidence":        [e.to_dict() for e in self.persistence.evidence],
            "networking_detected":         self.networking.detected,
            "network_score":               self.networking.score,
            "networking_evidence":         [e.to_dict() for e in self.networking.evidence],
            "command_execution_detected":  self.cmd_exec.detected,
            "command_score":               self.cmd_exec.score,
            "cmd_exec_evidence":           [e.to_dict() for e in self.cmd_exec.evidence],
            "credential_theft_detected":   self.credential_theft.detected,
            "credential_score":            self.credential_theft.score,
            "credential_theft_evidence":   [e.to_dict() for e in self.credential_theft.evidence],
            "worm_behavior_detected":      self.worm.detected,
            "worm_score":                  self.worm.score,
            "worm_evidence":               [e.to_dict() for e in self.worm.evidence],
            "stealer_detected":            self.stealer.detected,
            "stealer_score":               self.stealer.score,
            "stealer_evidence":            [e.to_dict() for e in self.stealer.evidence],
            "rat_detected":                self.rat.detected,
            "rat_score":                   self.rat.score,
            "rat_evidence":                [e.to_dict() for e in self.rat.evidence],
            "family_likelihoods":          self.family_likelihoods,
            "top_family":                  self.top_family,
            "dotnet_threat_score":         self.dotnet_threat_score,
            "dotnet_threat_level":         self.dotnet_threat_level,
            "total_indicators_fired":      len(self.all_evidence),
        }
        return d

    def to_forensic_report(self) -> Dict[str, Any]:
        """
        Genera el reporte forense completo (Fase 2 del spec).

        Formato exacto solicitado:
        {
          "reflection_detected": {
            "value": true,
            "evidence": [{"source": "MemberRef", "value": "...", ...}]
          }, ...
        }
        """
        def indicator_block(ind: BehaviorIndicator) -> dict:
            return {
                "value":    ind.detected,
                "score":    ind.score,
                "evidence": [e.to_dict() for e in ind.evidence],
            }

        return {
            "reflection_detected":        indicator_block(self.reflection),
            "dynamic_loading_detected":   indicator_block(self.dynamic_loading),
            "injection_detected":         indicator_block(self.injection),
            "persistence_detected":       indicator_block(self.persistence),
            "networking_detected":        indicator_block(self.networking),
            "command_execution_detected": indicator_block(self.cmd_exec),
            "credential_theft_detected":  indicator_block(self.credential_theft),
            "worm_behavior_detected":     indicator_block(self.worm),
            "stealer_detected":           indicator_block(self.stealer),
            "rat_detected":               indicator_block(self.rat),
            "embedded_resources": {
                "value":    self.embedded_resources.detected,
                "score":    self.embedded_resources.score,
                "evidence": [e.to_dict() for e in self.embedded_resources.evidence],
                "resource_count":    self.resource_count,
                "embedded_pe_count": self.embedded_pe_count,
                "encrypted_count":   self.encrypted_resource_count,
            },
            "threat_score_breakdown": {
                "injection":          self._WEIGHTS.get("injection", 0) if self.injection.detected else 0,
                "persistence":        self._WEIGHTS.get("persistence", 0) if self.persistence.detected else 0,
                "rat":                self._WEIGHTS.get("rat", 0) if self.rat.detected else 0,
                "networking":         self._WEIGHTS.get("networking", 0) if self.networking.detected else 0,
                "cmd_exec":           self._WEIGHTS.get("cmd_exec", 0) if self.cmd_exec.detected else 0,
                "credential_theft":   self._WEIGHTS.get("credential_theft", 0) if self.credential_theft.detected else 0,
                "dynamic_loading":    self._WEIGHTS.get("dynamic_loading", 0) if self.dynamic_loading.detected else 0,
                "stealer":            self._WEIGHTS.get("stealer", 0) if self.stealer.detected else 0,
                "worm":               self._WEIGHTS.get("worm", 0) if self.worm.detected else 0,
                "reflection":         self._WEIGHTS.get("reflection", 0) if self.reflection.detected else 0,
                "embedded_resources": self._WEIGHTS.get("embedded_resources", 0) if self.embedded_resources.detected else 0,
                "total_raw":          self.dotnet_threat_score,
                "level":              self.dotnet_threat_level,
            },
            "family_likelihoods": self.family_likelihoods,
            "top_family":         self.top_family,
        }

    # Referencia a los pesos del analyzer (se inyecta desde ILBehavioralAnalyzer)
    _WEIGHTS: Dict[str, int] = field(default_factory=dict)



# ─────────────────────────────────────────────────────────────────────────────
# ILBehavioralAnalyzer — Motor principal con trazabilidad forense
# ─────────────────────────────────────────────────────────────────────────────

class ILBehavioralAnalyzer:
    """
    Analizador de comportamiento semántico de ensamblados .NET.

    Estrategia de búsqueda en dos capas:

    Capa 1 — CLR Tables (alta confianza):
        Usa ClrStreamExtractor para parsear directamente:
        - MemberRef: nombres de métodos llamados
        - TypeRef: tipos externos instanciados
        - AssemblyRef: namespaces importados
        - ModuleRef/PInvoke: DLLs nativas invocadas
        - #Strings heap: nombres de tipos/métodos propios
        - #US heap: strings literales usadas en el código IL

    Capa 2 — Fallback de bytes (confianza reducida):
        Si el CLR parsing falla o no produce tokens suficientes,
        busca patterns en bytes raw con confidence="low" y
        source="Fallback". El veredicto sigue siendo válido pero
        se marca para revisión manual.

    Cada Evidence generada tiene source, value, location y confidence,
    lo que permite auditoría forense completa por cada indicador.
    """

    _THREAT_WEIGHTS: Dict[str, int] = {
        "injection":         25,
        "persistence":       15,
        "rat":               15,
        "networking":        10,
        "cmd_exec":          10,
        "credential_theft":  10,
        "dynamic_loading":    8,
        "stealer":            5,
        "worm":               5,
        "reflection":         5,
        "embedded_resources": 5,
    }
    _THREAT_MAX = sum(_THREAT_WEIGHTS.values())   # 113

    _THREAT_LEVELS: List[Tuple[int, str]] = [
        (75, "CRITICAL"),
        (50, "HIGH"),
        (25, "MEDIUM"),
        (0,  "LOW"),
    ]

    _SEARCH_LIMIT = 20 * 1024 * 1024

    def __init__(self) -> None:
        self._extractor = ClrStreamExtractor()

    def analyze(self, raw_data: bytes, pe_obj=None) -> ILBehavioralReport:
        """
        Analiza el comportamiento semántico de un ensamblado .NET.

        Proceso:
            1. Extrae CLR tokens (MemberRef, TypeRef, AssemblyRef, etc.)
            2. Para cada categoría, busca en los tokens con trazabilidad.
            3. Si CLR parsing falla → fallback a búsqueda de bytes.
            4. Analiza recursos embebidos con pefile.
            5. Calcula scores, family likelihoods, threat score.
        """
        report = ILBehavioralReport()
        report._WEIGHTS = self._THREAT_WEIGHTS
        data = raw_data[:self._SEARCH_LIMIT]

        try:
            # ── Capa 1: Extraer tokens CLR ────────────────────────────
            tokens = self._extractor.extract(data, pe_obj)
            has_clr_tokens = (
                tokens is not None
                and (
                    len(tokens.member_refs) > 0
                    or len(tokens.type_refs) > 0
                    or len(tokens.assembly_refs) > 0
                    or len(tokens.strings_heap) > 0
                    or len(tokens.user_strings) > 0
                )
            )

            if has_clr_tokens:
                logger.info(
                    "ILAnalyzer: CLR tokens extraídos — "
                    "member_refs=%d type_refs=%d assembly_refs=%d "
                    "strings=%d us=%d pinvoke=%d",
                    len(tokens.member_refs),
                    len(tokens.type_refs),
                    len(tokens.assembly_refs),
                    len(tokens.strings_heap),
                    len(tokens.user_strings),
                    len(tokens.pinvoke_refs),
                )
                search_fn = self._search_clr_tokens
            else:
                logger.warning(
                    "ILAnalyzer: CLR parsing falló o no produjo tokens, "
                    "usando fallback de bytes (confidence=low)"
                )
                tokens = ClrTokens()   # vacío
                search_fn = self._search_bytes_fallback

            # ── Categorías M2-M12 ─────────────────────────────────────
            report.reflection      = search_fn(data, tokens, _M2_REFLECTION,      max_score=30)
            report.dynamic_loading = search_fn(data, tokens, _M3_DYNAMIC_LOADING, max_score=30)
            report.injection       = search_fn(data, tokens, _M5_INJECTION,       max_score=50)
            report.persistence     = search_fn(data, tokens, _M6_PERSISTENCE,     max_score=40)
            report.networking      = search_fn(data, tokens, _M7_NETWORKING,      max_score=40)
            report.cmd_exec        = search_fn(data, tokens, _M8_CMD_EXEC,        max_score=40)
            report.credential_theft= search_fn(data, tokens, _M9_CREDENTIAL,      max_score=40)
            report.worm            = search_fn(data, tokens, _M10_WORM,           max_score=30)
            report.stealer         = search_fn(data, tokens, _M11_STEALER,        max_score=30)
            report.rat             = search_fn(data, tokens, _M12_RAT,            max_score=40)

            # ── M4: Embedded Resources ─────────────────────────────────
            self._analyze_resources(data, pe_obj, report)

            # ── Consolidar evidencias ──────────────────────────────────
            report.all_evidence = self._collect_evidence(report)

            # ── M13: Family Likelihoods ────────────────────────────────
            report.family_likelihoods, report.top_family = self._score_families(report)

            # ── M14: Threat Score ──────────────────────────────────────
            report.dotnet_threat_score, report.dotnet_threat_level = (
                self._compute_threat_score(report)
            )

            logger.info(
                "ILAnalyzer: threat_score=%d (%s) | family=%s | indicators=%d",
                report.dotnet_threat_score,
                report.dotnet_threat_level,
                report.top_family or "unknown",
                len(report.all_evidence),
            )

        except Exception as exc:
            logger.error("ILBehavioralAnalyzer: error inesperado: %s", exc)

        return report

    # ─────────────────────────────────────────────────────────────────
    # Capa 1: Búsqueda en tokens CLR (alta confianza)
    # ─────────────────────────────────────────────────────────────────

    def _search_clr_tokens(
        self,
        data: bytes,
        tokens: ClrTokens,
        patterns: List[Tuple],
        max_score: int,
    ) -> BehaviorIndicator:
        """
        Busca patrones en los tokens CLR extraídos.

        Para cada patrón, consulta SOLO los streams donde ese indicador
        tiene sentido (definido en la tupla de configuración).

        Asigna confidence según el stream de origen.
        """
        indicator = BehaviorIndicator()
        found_values: set = set()   # Evitar duplicados

        # Construir índices invertidos por fuente para búsqueda eficiente
        source_map: Dict[str, List[Tuple[str, str, int]]] = {
            "MemberRef":         tokens.member_refs,
            "TypeRef":           tokens.type_refs,
            "AssemblyRef":       tokens.assembly_refs,
            "ModuleRef/PInvoke": tokens.pinvoke_refs,
            "StringsHeap":       tokens.strings_heap,
            "UserString":        tokens.user_strings,
        }

        for pattern_lower, description, valid_sources in patterns:
            for source_name in valid_sources:
                token_list = source_map.get(source_name, [])
                for (value, _, index) in token_list:
                    val_lower = value.lower()
                    if pattern_lower in val_lower:
                        key = f"{pattern_lower}:{source_name}"
                        if key in found_values:
                            continue
                        found_values.add(key)

                        confidence = _SOURCE_CONFIDENCE.get(source_name, "low")
                        location = f"{source_name} #{index}"

                        ev = Evidence(
                            source=source_name,
                            value=value[:120],    # truncar para legibilidad
                            location=location,
                            confidence=confidence,
                        )
                        indicator.evidence.append(ev)
                        break   # Un hit por pattern es suficiente

        if indicator.evidence:
            indicator.detected = True
            # Peso por confianza: high=3, medium=2, low=1
            weighted = sum(
                3 if e.confidence == "high"
                else 2 if e.confidence == "medium"
                else 1
                for e in indicator.evidence
            )
            indicator.score = min(weighted * 3, max_score)

        return indicator

    # ─────────────────────────────────────────────────────────────────
    # Capa 2: Fallback de bytes (confianza reducida)
    # ─────────────────────────────────────────────────────────────────

    def _search_bytes_fallback(
        self,
        data: bytes,
        tokens: ClrTokens,
        patterns: List[Tuple],
        max_score: int,
    ) -> BehaviorIndicator:
        """
        Búsqueda plana en bytes cuando el CLR parsing no produce tokens.

        Todas las evidencias se marcan como confidence="low" y
        source="Fallback" para que el analista sepa que requieren
        verificación manual con un desensamblador .NET.
        """
        indicator = BehaviorIndicator()
        data_lower = data.lower()

        for pattern_lower, description, _ in patterns:
            pattern_bytes = pattern_lower.encode("ascii", errors="replace")
            if pattern_bytes in data_lower:
                # Buscar la offset de la primera ocurrencia
                off = data_lower.find(pattern_bytes)
                ev = Evidence(
                    source="Fallback",
                    value=description,
                    location=f"raw_offset=0x{off:x}",
                    confidence="low",
                )
                indicator.evidence.append(ev)
                continue

            # Unicode LE fallback
            unicode_pat = b"".join(bytes([b, 0]) for b in pattern_bytes)
            if unicode_pat in data:
                off = data.find(unicode_pat)
                ev = Evidence(
                    source="Fallback",
                    value=f"{description} [utf16le]",
                    location=f"raw_offset=0x{off:x}",
                    confidence="low",
                )
                indicator.evidence.append(ev)

        if indicator.evidence:
            indicator.detected = True
            indicator.score = min(len(indicator.evidence) * 3, max_score)

        return indicator

    # ─────────────────────────────────────────────────────────────────
    # M4: Embedded Resource Analyzer
    # ─────────────────────────────────────────────────────────────────

    def _analyze_resources(
        self, data: bytes, pe_obj, report: ILBehavioralReport
    ) -> None:
        """Analiza recursos embebidos del PE buscando payloads ocultos."""
        try:
            import pefile
            pe = pe_obj
            if pe is None:
                try:
                    pe = pefile.PE(data=data, fast_load=True)
                    pe.parse_data_directories(
                        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
                    )
                except Exception:
                    return

            if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                return

            entropies: List[float] = []

            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if not hasattr(res_type, "directory"):
                    continue
                for res_id in res_type.directory.entries:
                    if not hasattr(res_id, "directory"):
                        continue
                    for res_lang in res_id.directory.entries:
                        try:
                            de = res_lang.data
                            rva  = de.struct.OffsetToData
                            size = de.struct.Size
                            if size < 64:
                                continue
                            report.resource_count += 1
                            offset = pe.get_offset_from_rva(rva)
                            if offset is None:
                                continue
                            res_bytes = data[offset:offset + min(size, 2 * 1024 * 1024)]
                            if not res_bytes:
                                continue

                            ent = self._entropy(res_bytes)
                            entropies.append(ent)

                            def add_res_ev(desc: str, conf: str = "high"):
                                ev = Evidence(
                                    source="EmbeddedResource",
                                    value=desc,
                                    location=f"resource_offset=0x{offset:x} size={size}",
                                    confidence=conf,
                                )
                                report.embedded_resources.evidence.append(ev)

                            if res_bytes[:2] == b"MZ":
                                report.embedded_pe_count += 1
                                add_res_ev(f"PE directo (MZ header) — entropy={ent:.2f}")
                            elif b"BSJB" in res_bytes[:512]:
                                report.embedded_assembly_count += 1
                                add_res_ev(f"Assembly .NET embebido (BSJB) — entropy={ent:.2f}")
                            elif res_bytes[:2] == b"\x1f\x8b":
                                try:
                                    dec = zlib.decompress(res_bytes, wbits=47)
                                    if dec[:2] == b"MZ":
                                        report.embedded_pe_count += 1
                                        add_res_ev(f"PE GZIP-comprimido (MZ post-decomp) — entropy={ent:.2f}")
                                except Exception:
                                    pass
                            elif res_bytes[:2] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
                                try:
                                    dec = zlib.decompress(res_bytes)
                                    if dec[:2] == b"MZ":
                                        report.embedded_pe_count += 1
                                        add_res_ev(f"PE zlib-comprimido (MZ post-decomp) — entropy={ent:.2f}")
                                except Exception:
                                    pass

                            if ent > 7.2 and size > 1024:
                                report.encrypted_resource_count += 1
                                add_res_ev(
                                    f"Alta entropía: {ent:.4f} > 7.2 (posible payload cifrado)",
                                    conf="medium",
                                )
                        except Exception:
                            continue

            if entropies:
                report.resource_entropy_avg = sum(entropies) / len(entropies)

            total_suspicious = (
                report.embedded_pe_count
                + report.embedded_assembly_count
                + report.encrypted_resource_count
            )
            if total_suspicious > 0:
                report.embedded_resources.detected = True
                report.embedded_resources.score = min(total_suspicious * 10, 30)

        except Exception as exc:
            logger.debug("ILAnalyzer._analyze_resources error: %s", exc)

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq: Dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)

    # ─────────────────────────────────────────────────────────────────
    # M13, M14, M16 — scoring (idénticos a versión anterior)
    # ─────────────────────────────────────────────────────────────────

    def _score_families(
        self, report: ILBehavioralReport
    ) -> Tuple[Dict[str, int], str]:
        active: Dict[str, bool] = {
            "reflection":       report.reflection.detected,
            "dynamic_loading":  report.dynamic_loading.detected,
            "injection":        report.injection.detected,
            "persistence":      report.persistence.detected,
            "networking":       report.networking.detected,
            "cmd_exec":         report.cmd_exec.detected,
            "credential_theft": report.credential_theft.detected,
            "worm":             report.worm.detected,
            "stealer":          report.stealer.detected,
            "rat":              report.rat.detected,
        }
        raw_scores: Dict[str, int] = {fam: 0 for fam in _FAMILY_MAX}
        for indicator, is_active in active.items():
            if not is_active:
                continue
            for fam, weight in _FAMILY_WEIGHTS.get(indicator, {}).items():
                raw_scores[fam] = raw_scores.get(fam, 0) + weight
        likelihoods: Dict[str, int] = {}
        for fam, raw in raw_scores.items():
            max_val = _FAMILY_MAX.get(fam, 100)
            likelihoods[fam] = min(100, round((raw / max_val) * 100)) if max_val > 0 else 0
        top = max(likelihoods, key=lambda k: likelihoods[k]) if likelihoods else ""
        if likelihoods.get(top, 0) < 20:
            top = ""
        return likelihoods, top

    def _compute_threat_score(
        self, report: ILBehavioralReport
    ) -> Tuple[int, str]:
        raw = sum(
            self._THREAT_WEIGHTS[key]
            for key, indicator in [
                ("injection",         report.injection),
                ("persistence",       report.persistence),
                ("rat",               report.rat),
                ("networking",        report.networking),
                ("cmd_exec",          report.cmd_exec),
                ("credential_theft",  report.credential_theft),
                ("dynamic_loading",   report.dynamic_loading),
                ("stealer",           report.stealer),
                ("worm",              report.worm),
                ("reflection",        report.reflection),
                ("embedded_resources",report.embedded_resources),
            ]
            if indicator.detected
        )
        normalized = min(100, round((raw / self._THREAT_MAX) * 100))
        level = "LOW"
        for threshold, lv in self._THREAT_LEVELS:
            if normalized >= threshold:
                level = lv
                break
        return normalized, level

    def _collect_evidence(self, report: ILBehavioralReport) -> List[str]:
        evidence: List[str] = []
        for cat, ind in [
            ("REFLECTION",       report.reflection),
            ("DYNAMIC_LOADING",  report.dynamic_loading),
            ("INJECTION",        report.injection),
            ("PERSISTENCE",      report.persistence),
            ("NETWORKING",       report.networking),
            ("CMD_EXEC",         report.cmd_exec),
            ("CREDENTIAL_THEFT", report.credential_theft),
            ("WORM",             report.worm),
            ("STEALER",          report.stealer),
            ("RAT",              report.rat),
        ]:
            for ev in ind.evidence[:5]:
                evidence.append(
                    f"[{cat}] {ev.source}:{ev.location} → {ev.value} ({ev.confidence})"
                )
        return evidence

