"""
security/yara_scanner.py — Motor de firmas YARA para detección determinista.

YARA actúa como la primera línea de defensa del sistema. Antes de gastar
recursos en la extracción de features ML, revisamos si el archivo coincide
con alguna firma conocida de malware.

* PARA JUNIORS — ¿Por qué YARA antes que el modelo ML?
    El modelo ML de ShadowNet es excelente para detectar malware desconocido
    (zero-day), pero puede ser engañado por técnicas de evasión (packing,
    obfuscación). Sin embargo, las familias de malware conocidas (WannaCry,
    Mirai, njRAT) dejan firmas únicas en su código que YARA detecta de forma
    determinista y sin falsas negativas para las firmas que se tienen.

    Flujo ideal:
        YARA match → MALWARE CONFIRMADO (alta confianza, sin necesitar ML)
        YARA sin match → Proceder con extracción de features + ONNX

📁 Reglas YARA incluidas (security/yara_rules/):
    - trojans.yar       : Firmas de troyanos de acceso remoto (RATs)
    - spyware.yar       : Keyloggers, stealers de credenciales
    - worms.yar         : Gusanos de red, auto-propagación
    - ransomware.yar    : Ransomware conocido (WannaCry, Petya, LockBit)
    - packers.yar       : Empacadores y protectores de código
    - generic_malware.yar: Técnicas genéricas (process injection, shellcode)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from utils.logger import setup_logger

logger = setup_logger(__name__)

# Ruta por defecto a las reglas YARA en el proyecto
_DEFAULT_RULES_DIR = Path(__file__).parent / "yara_rules"


@dataclass
class YaraMatch:
    """Representa una coincidencia de regla YARA."""
    rule_name: str
    tags: List[str]
    meta: dict
    category: str  # "trojan", "spyware", "worm", "ransomware", etc.


@dataclass
class YaraScanResult:
    """Resultado completo del escaneo YARA sobre un archivo."""
    has_matches: bool
    matches: List[YaraMatch] = field(default_factory=list)
    scan_time_ms: float = 0.0
    error: Optional[str] = None

    @property
    def threat_names(self) -> List[str]:
        """Lista de nombres de amenazas detectadas."""
        return [m.rule_name for m in self.matches]

    @property
    def categories(self) -> List[str]:
        """Categorías únicas de malware detectadas."""
        return list({m.category for m in self.matches})


class YaraScanner:
    """
    Motor de escaneo con reglas YARA.

    Se inicializa una sola vez al arrancar el servidor y mantiene
    las reglas compiladas en memoria para un escaneo eficiente.

    Uso:
        scanner = YaraScanner()
        result = scanner.scan(Path("/tmp/malware.exe"))
        if result.has_matches:
            print(f"Malware detectado: {result.threat_names}")
    """

    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        self.rules_dir = rules_dir or _DEFAULT_RULES_DIR
        self._rules = None
        self._rules_count = 0
        self._load_rules()

    # ------------------------------------------------------------------
    # API Pública
    # ------------------------------------------------------------------

    def scan(self, file_path: Path) -> YaraScanResult:
        """
        Escanea un archivo con todas las reglas YARA compiladas.

        Args:
            file_path: Ruta al archivo a escanear.

        Returns:
            YaraScanResult con todas las coincidencias encontradas.
        """
        if self._rules is None:
            logger.warning("No hay reglas YARA cargadas. El escaneo YARA será omitido.")
            return YaraScanResult(has_matches=False, error="No YARA rules loaded")

        start = time.perf_counter()
        try:
            matches = self._rules.match(str(file_path), timeout=30)
            elapsed_ms = (time.perf_counter() - start) * 1000

            if not matches:
                return YaraScanResult(has_matches=False, scan_time_ms=elapsed_ms)

            parsed = [self._parse_match(m) for m in matches]
            logger.warning(
                "YARA: %d regla(s) coincidieron en %s — Amenazas: %s",
                len(parsed),
                file_path.name,
                [m.rule_name for m in parsed],
            )
            return YaraScanResult(has_matches=True, matches=parsed, scan_time_ms=elapsed_ms)

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.error("Error durante escaneo YARA de %s: %s", file_path.name, exc)
            return YaraScanResult(has_matches=False, scan_time_ms=elapsed_ms, error=str(exc))

    def scan_bytes(self, raw_data: bytes, label: str = "buffer") -> YaraScanResult:
        """
        Escanea un buffer de bytes (útil para archivos desempacados en memoria).

        Args:
            raw_data: Bytes del archivo a analizar.
            label: Etiqueta para los logs (nombre de archivo, etc.).
        """
        if self._rules is None:
            return YaraScanResult(has_matches=False, error="No YARA rules loaded")

        start = time.perf_counter()
        try:
            matches = self._rules.match(data=raw_data, timeout=30)
            elapsed_ms = (time.perf_counter() - start) * 1000

            if not matches:
                return YaraScanResult(has_matches=False, scan_time_ms=elapsed_ms)

            parsed = [self._parse_match(m) for m in matches]
            logger.warning(
                "YARA (en memoria): %d regla(s) en %s — %s",
                len(parsed), label, [m.rule_name for m in parsed]
            )
            return YaraScanResult(has_matches=True, matches=parsed, scan_time_ms=elapsed_ms)

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return YaraScanResult(has_matches=False, scan_time_ms=elapsed_ms, error=str(exc))

    @property
    def rules_loaded(self) -> int:
        """Número de reglas YARA cargadas."""
        return self._rules_count

    @property
    def is_available(self) -> bool:
        """True si el scanner está operativo con reglas cargadas."""
        return self._rules is not None and self._rules_count > 0

    # ------------------------------------------------------------------
    # Implementación Privada
    # ------------------------------------------------------------------

    def _load_rules(self) -> None:
        """
        Compila las reglas .yar del directorio, una por una.

        Estrategia tolerante a fallos: si un archivo tiene un error de
        sintaxis YARA (ej: string no referenciado), se salta ese archivo
        y continúa cargando los demás. Esto garantiza que un error en
        una sola regla no deshabilite todo el motor YARA.
        """
        try:
            import yara
        except ImportError:
            logger.error(
                "El módulo 'yara-python' no está instalado. "
                "Instalar con: pip install yara-python"
            )
            return

        if not self.rules_dir.exists():
            logger.warning("Directorio de reglas YARA no encontrado: %s", self.rules_dir)
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            logger.info(
                "Directorio creado: %s. Agrega archivos .yar para activar el scanner.",
                self.rules_dir,
            )
            return

        yar_files = list(self.rules_dir.rglob("*.yar"))
        if not yar_files:
            logger.warning(
                "No se encontraron archivos .yar en %s. "
                "Descarga reglas de: https://github.com/Yara-Rules/rules",
                self.rules_dir,
            )
            return

        # Compilar cada archivo individualmente y acumular los válidos
        valid_rules: list = []
        failed = 0

        for yar_path in yar_files:
            try:
                compiled = yara.compile(filepath=str(yar_path))
                valid_rules.append((yar_path.stem, compiled))
                logger.debug("YARA: %s cargado OK", yar_path.name)
            except Exception as exc:
                failed += 1
                logger.warning(
                    "YARA: Error compilando %s (se omite): %s",
                    yar_path.name,
                    exc,
                )

        if not valid_rules:
            logger.error("YARA: Ningún archivo de reglas pudo compilarse.")
            return

        # Recompilar todos los válidos juntos para escaneo unificado
        valid_paths = {stem: str(p) for (stem, _), p in zip(valid_rules, yar_files) if True}
        # Reconstruir el dict correctamente
        valid_file_dict: dict = {}
        for yar_path in yar_files:
            try:
                yara.compile(filepath=str(yar_path))  # Validar
                valid_file_dict[yar_path.stem] = str(yar_path)
            except Exception:
                pass

        try:
            self._rules = yara.compile(filepaths=valid_file_dict)
            self._rules_count = len(valid_file_dict)
            logger.info(
                "YARA: %d/%d archivo(s) de reglas cargados exitosamente%s.",
                self._rules_count,
                len(yar_files),
                f" ({failed} con errores omitidos)" if failed else "",
            )
        except Exception as exc:
            logger.error("Error en compilación final YARA: %s", exc)
            self._rules = None

    @staticmethod
    def _parse_match(match) -> YaraMatch:
        """Convierte un objeto yara.Match en nuestro dataclass YaraMatch."""
        meta = dict(match.meta) if hasattr(match, "meta") else {}
        tags = list(match.tags) if hasattr(match, "tags") else []

        # Inferir categoría desde el nombre de la regla o los tags
        rule_lower = match.rule.lower()
        tag_lower = " ".join(tags).lower()
        combined = rule_lower + " " + tag_lower

        if "ransomware" in combined:
            category = "ransomware"
        elif "trojan" in combined or "rat" in combined or "backdoor" in combined:
            category = "trojan"
        elif "spyware" in combined or "keylog" in combined or "stealer" in combined:
            category = "spyware"
        elif "worm" in combined:
            category = "worm"
        elif "packer" in combined or "protector" in combined:
            category = "packer"
        else:
            category = "malware"

        return YaraMatch(
            rule_name=match.rule,
            tags=tags,
            meta=meta,
            category=category,
        )
