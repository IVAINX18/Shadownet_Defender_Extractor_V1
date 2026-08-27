# Design Document — ShadowNet Defender F2 Hardening Heurístico

## Overview

F2 endurece 6 superficies de ataque/evaluación sin tocar el modelo ONNX ni el vector 2381. Todas las tareas son aditivas: nuevos campos en `overlay_analysis`/`heuristic_assessment`, nuevo `whitelist.json`, cifrado opcional en cuarentena y validador post-LLM. F1 ya garantiza invariante `operational_status ∈ {CLEAN,SUSPICIOUS,DANGEROUS}` y timeout extractor.

```
F2 Scope:
  T-05 YARA whitelist         → security/yara_scanner.py + configs/whitelist.json + core/heuristics/
  T-06 Block entropy          → core/overlay/analyzer.py + core/heuristics/
  T-07 Installer spoof        → core/overlay/analyzer.py + core/heuristics/
  T-08 Quarantine encryption  → core/quarantine/manager.py
  T-09 ML hardening           → core/heuristics/ + docs/academico/13_limitaciones.md
  T-10 LLM validation         → core/llm/ollama_client.py + core/llm/explanation_service.py
```

---

## Architecture

### Componentes afectados

```
security/yara_scanner.py          ← T-05: is_whitelisted()
configs/whitelist.json            ← T-05: nuevo, cargado en YaraScanner.__init__
core/overlay/analyzer.py          ← T-06: block entropy; T-07: installer spoof flag
core/heuristics/risk_engine.py    ← T-05/T-06/T-07/T-09: nuevos indicadores
core/quarantine/manager.py        ← T-08: cifrado Fernet
core/llm/ollama_client.py         ← T-10: fix prod localhost validation
core/llm/explanation_service.py   ← T-10: llm_inconsistent + llm_confidence
docs/academico/13_limitaciones.md ← T-09: R-03/R-04 documentation
backend/app/services/scan_service.py ← sin cambios (F2 usa engine result)
```

### Diagrama de flujo — T-05 whitelist

```
scan_file()
  → _run_yara_phase()
      yara_scan = scanner.scan(file)  # has_matches?
      sha256 = _compute_sha256(file)
      if has_matches and scanner.is_whitelisted(sha256, yara_scan.matches):
          yara_result["whitelisted"] = True
          yara_result["operational_status"] = "SUSPICIOUS"  # no DANGEROUS
          yara_result["heuristic_assessment"]["whitelist_hit"] = True
      else:
          yara_result["operational_status"] = "DANGEROUS"
```

### Diagrama de flujo — T-06 block entropy

```
OverlayAnalyzer.analyze(raw_data):
  overlay = raw_data[overlay_offset:]
  overlay_entropy = shannon(overlay)              # global (existente)
  blocks = [overlay[i:i+64KB] for i in range(0, len(overlay), 64KB)]
  block_entropies = [shannon(b) for b in blocks]
  max_block_entropy = max(block_entropies) if blocks else 0
  high_entropy_block_ratio = sum(e > 7.2 for e in block_entropies) / len(blocks)

RiskEngine.assess(overlay_report):
  if overlay_report.high_entropy_block_ratio > 0.30 and overlay_report.overlay_ratio > 0.50:
      risk_score += 15
      triggered.append("block_entropy_anomaly")
```

### Diagrama de flujo — T-08 quarantine encryption

```
quarantine_file(file_path):
  sha256 = compute_sha256(file_path)
  key = _get_or_create_key()  # QUARANTINE_KEY env or ~/.shadownet/.quarantine.key (600)
  plaintext = file_path.read_bytes()
  if key and cryptography_available:
      ciphertext = Fernet(key).encrypt(plaintext)
      encrypted = True
  else:
      ciphertext = plaintext
      encrypted = False
  write(quarantine_path, ciphertext)
  write(meta_path, {sha256, encrypted, key_id, ...})
  chmod(quarantine_path, 0o600)
```

---

## Detailed Design

### T-05 — Whitelisting YARA

**Nuevo archivo:** `configs/whitelist.json`

```json
{
  "sha256": [
    "a3f5... (procexp64.exe)",
    "b7c2... (procmon64.exe)"
  ],
  "yara_exclusions": [
    {"rule": "Keylogger_Generic", "company": "Microsoft", "signer": "Microsoft Corporation"}
  ]
}
```

**Cambios en `security/yara_scanner.py`:**

```python
class YaraScanner:
    def __init__(self):
        self.whitelist = self._load_whitelist()  # configs/whitelist.json or {}

    def _load_whitelist(self) -> dict:
        try:
            p = Path(__file__).parent.parent / "configs" / "whitelist.json"
            if p.exists():
                return json.loads(p.read_text())
        except Exception as exc:
            logger.warning("Whitelist no cargado: %s", exc)
        return {"sha256": [], "yara_exclusions": []}

    def is_whitelisted(self, sha256: str, matches: list) -> bool:
        if sha256.lower() in {h.lower() for h in self.whitelist.get("sha256", [])}:
            return True
        # Exclusión por regla + company (requiere parse de PE CompanyName si disponible)
        for m in matches:
            for excl in self.whitelist.get("yara_exclusions", []):
                if m.rule_name == excl.get("rule"):
                    # Si hay verificación de signer, delegar a caller (RiskEngine)
                    return True  # conservador: si la regla está en exclusiones, whitelistea
        return False
```

**Cambios en `core/engine.py` `_run_yara_phase`:**

```python
sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
if yara_scan.has_matches and self._yara_scanner.is_whitelisted(sha256, yara_scan.matches):
    yara_result["operational_status"] = "SUSPICIOUS"
    yara_result["risk_level"] = "MEDIUM"
    yara_result["heuristic_assessment"] = {"whitelist_hit": True, "whitelisted": True}
    yara_result["details"]["whitelist_hit"] = True
```

**Tests:**

- `test_yara_whitelisted_no_dangerous`: mock Yara match + sha256 en whitelist → `operational_status != DANGEROUS`
- `test_procexp64_whitelisted_is_suspicious`: si `samples/procexp64.exe` existe, verificar que no sea `MALWARE` puro

### T-06 — Entropía por bloques

**Cambios en `core/overlay/analyzer.py`:**

```python
from collections import Counter
import math

def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

@dataclass
class OverlayReport:
    # existentes...
    max_block_entropy: float = 0.0
    high_entropy_block_ratio: float = 0.0
    block_count: int = 0

def _compute_block_entropy(self, overlay: bytes, block_size: int = 64*1024) -> tuple[float, float, int]:
    if not overlay:
        return 0.0, 0.0, 0
    blocks = [overlay[i:i+block_size] for i in range(0, len(overlay), block_size)]
    entropies = [_shannon(b) for b in blocks]
    max_e = max(entropies) if entropies else 0.0
    ratio = sum(1 for e in entropies if e > 7.2) / len(entropies) if entropies else 0.0
    return max_e, ratio, len(blocks)
```

Integrar en `analyze()` después de `overlay_entropy` y poblar `to_dict()`.

**Cambios en `core/heuristics/risk_engine.py`:**

```python
if overlay_report.high_entropy_block_ratio > 0.30 and overlay_report.overlay_ratio > 0.50:
    risk_score += 15
    triggered.append("block_entropy_anomaly: high_block_ratio=%.2f" % overlay_report.high_entropy_block_ratio)
```

**Tests:**

- `test_block_entropy_detects_segmented_overlay`: overlay sintético con bloques alternos 7.9/2.0 → `high_entropy_block_ratio≈0.5` y `block_entropy_anomaly` activo
- `test_section_coverage_anomaly`: PE con secciones que cubren >90% pero overlay 0 → no dispara

### T-07 — Endurecer descuento de instalador

**Cambios en `core/overlay/analyzer.py`:**

```python
# Antes: is_known_installer = bool(installer_type)
# Después:
if overlay_report.installer_type in ("NSIS", "InnoSetup"):
    if overlay_report.overlay_ratio > 0.93:
        overlay_report.installer_spoof_suspected = True
        overlay_report.is_known_installer = False  # no descuento
        logger.warning("Installer spoof sospechado: %s overlay=%.1f%%", installer_type, overlay_report.overlay_ratio*100)
    elif overlay_report.overlay_ratio > 0.90:
        # zona gris: requiere validación estructural adicional
        overlay_report.is_known_installer = self._validate_installer_structure(raw_data)
    else:
        overlay_report.is_known_installer = True
```

**Cambios en `core/heuristics/risk_engine.py`:**

```python
if overlay_report.installer_spoof_suspected:
    triggered.append("installer_spoof_suspected")
    # No aplicar descuento de instalador
else:
    if overlay_report.is_known_installer:
        risk_score = max(0, risk_score - 20)  # descuento existente
```

### T-08 — Cifrado de cuarentena

**Cambios en `core/quarantine/manager.py`:**

```python
def _get_or_create_key() -> bytes | None:
    env_key = os.getenv("QUARANTINE_KEY", "").strip()
    if env_key:
        return env_key.encode()  # debe ser Fernet key válida (44 chars base64)
    key_path = Path.home() / ".shadownet" / ".quarantine.key"
    if key_path.exists():
        return key_path.read_bytes().strip()
    try:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key)
        key_path.chmod(0o600)
        return key
    except ImportError:
        logger.warning("cryptography no instalada — cuarentena sin cifrado")
        return None

def quarantine_file(...):
    key = _get_or_create_key()
    # ... leer plaintext
    if key:
        try:
            from cryptography.fernet import Fernet
            data = Fernet(key).encrypt(plaintext)
            encrypted = True
        except Exception:
            data = plaintext
            encrypted = False
    # write data + meta {encrypted, sha256, key_id}
```

**Restore:**

```python
def restore_file(...):
    meta = json.loads(meta_path.read_text())
    data = quarantine_path.read_bytes()
    if meta.get("encrypted"):
        key = _get_or_create_key()
        if not key:
            return RestoreResult(success=False, error="DECRYPTION_FAILED")
        from cryptography.fernet import Fernet
        data = Fernet(key).decrypt(data)
    # verificar sha256
```

### T-09 — Hardening ML

**Docs:**

Actualizar `docs/academico/13_limitaciones.md` R-04:

```markdown
### R-04 — Colisiones en feature hashing de imports (1280 buckets)
Con 1280 buckets para 1000+ APIs, colisión esperada ≈ 30%. Cambio a 2048+ requiere reentrenamiento
y regeneración de `models/scaler.pkl` + `models/best_model.onnx` — fuera de alcance F2. Mitigación F2:
correlación `num_imports==0 + executable_sections==1` en RiskEngine.
```

**RiskEngine:**

```python
if details.get("num_imports", 0) == 0 and details.get("executable_sections", 0) == 1:
    triggered.append("suspicious_loader_no_imports")
    risk_score += 10
```

### T-10 — Validación LLM

**Fix `core/llm/ollama_client.py`:**

```python
# En OllamaClientConfig.__post_init__ o en generate():
if os.getenv("ENVIRONMENT", "dev").lower() == "prod":
    url = os.getenv("OLLAMA_BASE_URL", self.base_url)
    if "127.0.0.1" in url or "localhost" in url:
        raise RuntimeError("OLLAMA_BASE_URL apunta a localhost en producción")
```

**Validador `core/llm/explanation_service.py`:**

```python
def _validate_llm_response(parsed: dict, scan_result: dict) -> dict:
    risk_level = scan_result.get("risk_level", "LOW").upper()
    threat_level = parsed.get("threat_level", "").lower()
    inconsistent = False
    if risk_level in ("CRITICAL", "HIGH") and threat_level in ("none", "low"):
        inconsistent = True
    # llm_confidence: cita algún indicador real?
    indicators = ["overlay_ratio", "overlay_entropy", "yara", "injection", "persistence", "risk_score"]
    text = json.dumps(parsed).lower()
    hits = sum(1 for ind in indicators if ind in text)
    confidence = min(1.0, hits / 3.0)
    return {"llm_inconsistent": inconsistent, "llm_confidence": round(confidence, 2)}
```

Inyectar en `explain_scan_result()` antes de retornar.

---

## Correctness Properties

### Propiedad 1 — Whitelist nunca produce DANGEROUS por YARA solo (T-05)
Para todo `sha256 ∈ whitelist.sha256` con `has_matches=True`: `operational_status != DANGEROUS`.

### Propiedad 2 — Block entropy detecta segmentado (T-06)
Para todo overlay con `high_entropy_block_ratio > 0.30` y `overlay_ratio > 0.50`: `block_entropy_anomaly ∈ triggered_indicators`.

### Propiedad 3 — Installer spoof no obtiene descuento (T-07)
Para todo `overlay_ratio > 0.93` con magic NSIS/Inno: `is_known_installer == False` y `installer_spoof_suspected == True`.

### Propiedad 4 — Quarantine ciphertext no contiene plaintext (T-08)
Para todo archivo cuarentenado con clave disponible: `plaintext ∉ ciphertext` (bytes no contenidos literalmente).

### Propiedad 5 — Loader sin imports elevado (T-09)
Para todo PE con `num_imports==0` y `executable_sections==1`: `suspicious_loader_no_imports ∈ triggered_indicators` y `risk_score` incrementado.

### Propiedad 6 — LLM inconsistency flag (T-10)
Para todo `risk_level=CRITICAL` y `threat_level in {none,low}`: `llm_inconsistent == True`.

---

## Implementation Plan

Orden: T-05 → T-06 → T-07 → T-08 → T-09 → T-10 (T-05..T-07 tocan overlay/heuristics, hacer secuencial; T-08 y T-10 independientes pueden ir en paralelo).

1. **T-05** — crear `configs/whitelist.json` + `is_whitelisted()` en YaraScanner + hook en `_run_yara_phase` + tests
2. **T-06** — `max_block_entropy`/`high_entropy_block_ratio` en OverlayAnalyzer + indicador en RiskEngine + tests
3. **T-07** — `installer_spoof_suspected` en OverlayReport + lógica de no-descuento en RiskEngine + tests
4. **T-08** — `_get_or_create_key()` + encrypt en `quarantine_file()` + decrypt en `restore_file()` + tests
5. **T-09** — docs + indicador `suspicious_loader_no_imports` en RiskEngine + test
6. **T-10** — fix `ollama_client.py` prod localhost + validador en `explanation_service.py` + tests

Cada tarea termina con `pytest` sobre sus tests específicos antes de pasar a la siguiente. Verificación final: `pytest tests/ -v` 0 nuevos FAILED vs F1 baseline.
