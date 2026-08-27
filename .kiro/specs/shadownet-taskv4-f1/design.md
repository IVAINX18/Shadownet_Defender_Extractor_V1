# Design Document — ShadowNet Defender F1 Estabilización

## Overview

Este documento describe los cambios de diseño para las cuatro tareas de la fase F1 de ShadowNet Defender. El objetivo es estabilizar el sistema antes del despliegue V4, corrigiendo cuatro comportamientos críticos identificados en la auditoría TaskV4.

Las tareas son independientes entre sí con excepción de T-03 y T-04, que ambas tocan `core/engine.py`. Se pueden implementar en paralelo salvo esa coordinación. Ninguna tarea modifica `scaler.pkl`, `best_model.onnx` ni el contrato de 2381 dimensiones del extractor.

---

## Architecture

### Componentes afectados

```
core/integrations/n8n_client.py     ← T-01: lógica de condición de alerta
backend/app/services/scan_service.py ← T-01: _notify_n8n_if_malicious
backend/app/api/dependencies/auth.py ← T-02: manejo de excepciones JWT
backend/app/integrations/supabase_client.py ← T-02: NoSupabaseConfig ya existía
core/engine.py                       ← T-03: eliminar UNKNOWN; T-04: timeout extractor
core/heuristics/*                    ← T-03: verificar que risk engine nunca emite UNKNOWN
backend/app/schemas/dto.py           ← T-03: no exponer UNKNOWN como valor por defecto
extractors/extractor.py              ← T-04: envolver extract() con ThreadPoolExecutor
configs/settings.py                  ← T-04: añadir EXTRACTOR_TIMEOUT_SECONDS
tests/test_n8n_client.py             ← T-01: actualizar/añadir tests
tests/properties/test_n8n_properties.py ← T-01: reescribir prop16
tests/security/test_backend_security.py ← T-02: TestExpiredJWT ya existe, debe pasar
tests/unit/test_engine.py            ← T-03: test_yara_match_never_unknown
tests/test_extractors.py             ← T-04: test_extractor_timeout_fallback
```

### Diagrama de flujo — T-01 condición de alerta ampliada

```
send_scan_result(scan_result)
        │
        ├─ N8N_ALERT_ON_LABEL_ONLY == true?
        │       ├─ sí → alert iff label == "malicious"
        │       └─ no ↓
        │
        ├─ label == "malicious"?  → alert (event: malware_detected / malware_critical)
        │
        ├─ operational_status in N8N_ALERT_ON_STATUS?  → alert (event: dangerous_detected)
        │
        └─ else → skip (return False)
```

### Diagrama de flujo — T-04 timeout extractor en pipeline

```
_scan_file_internal(file_path)
        │
        ├─ FASE YARA  (sin cambio)
        ├─ FASE UPX   (sin cambio)
        │
        ├─ FASE ML ──→ _run_ml_phase()
        │       │
        │       └─ ThreadPoolExecutor(max_workers=1)
        │               ├─ extractor.extract(path) — timeout EXTRACTOR_TIMEOUT_SECONDS
        │               │       ├─ ok → inferencia ONNX normal
        │               │       └─ TimeoutError →
        │                               operational_status = "SUSPICIOUS"
        │                               degradation_reason = "extractor_timeout"
        │                               label = "UNKNOWN" → normalizado a SUSPICIOUS (T-03)
        │                               continuar pipeline
        │
        ├─ FASE OVERLAY (sin cambio)
        └─ FASE .NET / IL / BEHAVIORAL (sin cambio)
```

---

## Detailed Design

### T-01 — Condición de alerta n8n ampliada

**Archivo principal:** `core/integrations/n8n_client.py`

La función `send_scan_result` actualmente evalúa:
```python
should_alert = (result_val == "malicious") or (op_status == "DANGEROUS")
```

El problema es que el campo `op_status` ya está implementado correctamente en `n8n_client.py` (la condición `op_status == "DANGEROUS"` ya existe). El bug real está en `scan_service.py` en la función `_notify_n8n_if_malicious`, que filtra antes de llamar a `send_scan_result` y solo pasa el resultado cuando `result == "malicious"`, lo que hace que `send_scan_result` nunca reciba un `operational_status=DANGEROUS` con `label=BENIGN`.

**Cambio en `scan_service.py`:**

```python
def _notify_n8n(scan_result: ScanResult) -> None:
    """Envía alerta a N8N según operational_status o label."""
    try:
        from core.integrations.n8n_client import send_scan_result
        send_scan_result(scan_result.model_dump())
    except Exception as exc:
        logger.warning("Error enviando alerta N8N: %s", exc)
```

La lógica de filtrado se delega completamente a `send_scan_result` en `n8n_client.py`, que ya maneja la condición correcta.

**Cambio en `n8n_client.py` — parametrización por env:**

```python
# Leer lista de statuses que disparan alerta
_ALERT_ON_STATUS_DEFAULT = "DANGEROUS,SUSPICIOUS"

def _get_alert_statuses() -> frozenset[str]:
    raw = os.getenv("N8N_ALERT_ON_STATUS", _ALERT_ON_STATUS_DEFAULT)
    return frozenset(s.strip().upper() for s in raw.split(",") if s.strip())

def _get_alert_label_only() -> bool:
    return _to_bool(os.getenv("N8N_ALERT_ON_LABEL_ONLY"), default=False)
```

Condición de disparo actualizada:
```python
label_only = _get_alert_label_only()
alert_statuses = _get_alert_statuses()

if label_only:
    should_alert = (result_val == "malicious")
else:
    should_alert = (result_val == "malicious") or (op_status in alert_statuses)
```

**Nota sobre el estado actual de `n8n_client.py`:** La condición `op_status == "DANGEROUS"` ya existe en el archivo pero sin la parametrización por env. Se añade `N8N_ALERT_ON_STATUS` y `N8N_ALERT_ON_LABEL_ONLY` manteniendo compatibilidad retroactiva (el comportamiento por defecto no cambia).

**Tests a actualizar/añadir en `tests/test_n8n_client.py`:**

- `test_send_scan_result_skips_benign`: actualizar — ahora debe verificar que `result=benign` + `operational_status=CLEAN` sí skipea, pero `result=benign` + `operational_status=DANGEROUS` SÍ envía.
- `test_send_scan_result_sends_dangerous_benign_label` (nuevo): `operational_status=DANGEROUS` + `result=benign` → `True` cuando N8N habilitado.

**Propiedad Hypothesis en `tests/properties/test_n8n_properties.py`:**

Renombrar `test_prop16_non_alert_always_skip` a `non_critical_always_skip` y actualizar para que los valores no-críticos respeten `N8N_ALERT_ON_STATUS`:

```python
@given(
    result=st.sampled_from(["benign", "clean", "safe", ""]),
    op_status=st.sampled_from(["CLEAN", "UNKNOWN", "", "safe"]),
    ...
)
def non_critical_always_skip(result, op_status, filename, score):
    """result ∉ {malicious} y op_status ∉ N8N_ALERT_ON_STATUS → siempre False."""
    with patch.dict(os.environ, {"N8N_ALERT_ON_STATUS": "DANGEROUS,SUSPICIOUS"}, ...):
        r = send_scan_result({...})
    assert r is False
```

---

### T-02 — JWT expirado → 401 fail-secure

**Archivo principal:** `backend/app/api/dependencies/auth.py`

**Problema actual:** Cuando `SUPABASE_URL` y `SUPABASE_JWT_SECRET` están ambos vacíos, el código hace:
```python
raise HTTPException(status_code=500, detail="Configuración de autenticación incompleta...")
```

Esto viola el principio fail-secure. El fix es cambiar a 401.

**Cambio en `get_current_user`:**

```python
if not SUPABASE_URL and not SUPABASE_JWT_SECRET:
    logger.warning("Supabase no configurado — modo fail-secure (401)")
    raise HTTPException(
        status_code=401,
        detail="Autenticación no disponible. Configura SUPABASE_URL o SUPABASE_JWT_SECRET.",
    )
```

**Manejo de excepciones no controladas — añadir catch-all:**

```python
try:
    payload = _decode_token(token)
except pyjwt.ExpiredSignatureError:
    raise HTTPException(status_code=401, detail="Token expirado.")
except pyjwt.InvalidTokenError as exc:
    logger.warning("JWT inválido: %s", type(exc).__name__)
    raise HTTPException(status_code=401, detail="Token inválido.")
except Exception as exc:
    # Capturar cualquier excepción no anticipada (e.g., error de red en JWKS)
    logger.error("Error inesperado en validación JWT: %s", type(exc).__name__)
    raise HTTPException(status_code=401, detail="Error de autenticación.")
```

**Análisis del estado actual:** El archivo ya captura `ExpiredSignatureError` e `InvalidTokenError` correctamente. El único path que produce 500 es la verificación de config vacía. El fix principal es cambiar ese `status_code=500` a `401`.

**Test afectado:** `TestExpiredJWT::test_expired_token_rejected` — con el token `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.expired_signature_here` y sin `SUPABASE_URL`/`SUPABASE_JWT_SECRET` configurados, el endpoint debe retornar 401 (actualmente retorna 500 por la verificación de config).

---

### T-03 — Eliminar operational_status=UNKNOWN

**Archivo principal:** `core/engine.py`

**Análisis:** El estado `UNKNOWN` se inicializa en `_scan_file_internal`:
```python
"operational_status": "UNKNOWN",  # se sobreescribe en fases posteriores
```

El problema ocurre cuando la Fase YARA hace early-exit **antes** de que el Risk Engine establezca `operational_status`. El resultado YARA retornado en `_run_yara_phase` hereda el dict `result` que tiene `operational_status=UNKNOWN`.

**Cambio en `_run_yara_phase`:** Forzar `operational_status=DANGEROUS` en el resultado YARA:

```python
yara_result.update({
    ...
    "operational_status": "DANGEROUS",  # YARA match = DANGEROUS por diseño
    ...
})
```

**Cambio en el dict inicial de `_scan_file_internal`:** Cambiar el valor por defecto:

```python
"operational_status": "SUSPICIOUS",  # nunca UNKNOWN — T-03
```

Esto garantiza que incluso si el pipeline se interrumpe antes de que el Risk Engine corra, el resultado final nunca tendrá `UNKNOWN`.

**Cambio en `_run_ml_phase`:** Ya está correcto — en caso de fallo ONNX se establece `"SUSPICIOUS"`. Verificar que no queda ningún `"UNKNOWN"` hardcodeado.

**Cambio en el timeout del watchdog (`scan_file`):** El resultado de timeout actualmente tiene `"label": "UNKNOWN"`. Cambiar a:
```python
"label": "UNKNOWN",         # label puede ser UNKNOWN — no es operational_status
"operational_status": "SUSPICIOUS",  # ya correcto en el código actual
```

El campo `label` del motor interno puede seguir siendo `"UNKNOWN"` (es el label ML, no el operational_status). Es `operational_status` el que debe pertenecer al conjunto `{CLEAN, SUSPICIOUS, DANGEROUS}`.

**Cambio en `backend/app/schemas/dto.py`:** El DTO `ScanResult` no tiene un campo `operational_status` explícito (se incluye en la telemetría pero no como campo Pydantic). Verificar y documentar que si se añade, el validador rechaza `"UNKNOWN"`.

**Test nuevo:** `test_yara_match_never_unknown` en `tests/unit/test_engine.py`:
```python
def test_yara_match_never_unknown(tmp_path):
    """YARA early-exit nunca produce operational_status=UNKNOWN."""
    # Mock YARA match, verificar que operational_status != "UNKNOWN"
    ...
    assert result["operational_status"] != "UNKNOWN"
    assert result["operational_status"] == "DANGEROUS"
```

---

### T-04 — Timeout configurable para extractor

**Archivo principal:** `core/engine.py` — método `_run_ml_phase`

**Diseño:** El `extract_features()` se ejecuta en `_run_ml_phase`. Actualmente no tiene timeout interno. El watchdog de 60s en `scan_file` protege el pipeline completo, pero un extractor bloqueado consume ese tiempo entero.

**Cambio en `configs/settings.py`:**
```python
EXTRACTOR_TIMEOUT_SECONDS = int(os.getenv("EXTRACTOR_TIMEOUT_SECONDS", "15"))
```

**Cambio en `_run_ml_phase` en `core/engine.py`:**

```python
import concurrent.futures
from configs.settings import EXTRACTOR_TIMEOUT_SECONDS

def _run_ml_phase(self, analysis_path: Path, result: Dict[str, Any]) -> None:
    try:
        result["detection_phases"].append("ML_STATIC")
        
        # T-04: envolver extract() con timeout configurable
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.extractor.extract, str(analysis_path))
            try:
                features = future.result(timeout=EXTRACTOR_TIMEOUT_SECONDS)
            except concurrent.futures.TimeoutError:
                logger.warning(
                    "Extractor timeout (%ds) para %s → SUSPICIOUS",
                    EXTRACTOR_TIMEOUT_SECONDS, analysis_path.name,
                )
                result["operational_status"] = "SUSPICIOUS"
                result["details"]["degradation_reason"] = "extractor_timeout"
                result["label"] = "SUSPICIOUS"  # No es NOT_PE ni UNKNOWN
                return
        
        # ... resto del método sin cambios
```

**Relación con el watchdog:** El `EXTRACTOR_TIMEOUT_SECONDS` (15s default) opera dentro del watchdog global `ANALYSIS_TIMEOUT_SECONDS` (60s default). Son capas independientes:

```
scan_file() [watchdog 60s]
    └── _scan_file_internal()
            └── _run_ml_phase()
                    └── extractor.extract() [timeout 15s] ← T-04
```

**Test nuevo:** `test_extractor_timeout_fallback` en `tests/test_extractors.py`:
```python
def test_extractor_timeout_fallback(tmp_path):
    """Extractor timeout → operational_status=SUSPICIOUS + degradation_reason."""
    # Mock extractor.extract() que duerme más que el timeout
    # Verificar campos del resultado
    assert result["operational_status"] == "SUSPICIOUS"
    assert result["details"]["degradation_reason"] == "extractor_timeout"
```

---

## Correctness Properties

Basado en el análisis de testabilidad previo:

### Propiedad 1 — Non-critical inputs never alert (T-01)
Para todo `result ∉ {"malicious"}` y `operational_status ∉ N8N_ALERT_ON_STATUS`:
```
send_scan_result({"result": result, "operational_status": op_status, ...}) == False
```
Implementada como `non_critical_always_skip` en Hypothesis.

### Propiedad 2 — N8N disabled always False (T-01, ya existente como prop18)
Para todo input con `N8N_ENABLED=false`:
```
send_scan_result(any_input) == False
```

### Propiedad 3 — operational_status invariant (T-03)
Para todo resultado de escaneo completado por el Engine:
```
result["operational_status"] ∈ {"CLEAN", "SUSPICIOUS", "DANGEROUS"}
```
Testable como propiedad sobre múltiples inputs simulados de fases del pipeline.

### Propiedad 4 — Auth never 500 (T-02)
Para todo token (expirado, malformado, vacío) con cualquier combinación de config Supabase:
```
HTTP response status ∈ {401, 200}  (nunca 500 en path de auth)
```

### Propiedad 5 — Round-trip serialización payload (ya existente como prop17)
Para todo payload de n8n:
```
json.dumps(_safe_json(payload)) no lanza ValueError
```

---

## Implementation Plan

Las tareas se implementan en orden T-02 → T-01 → T-03 → T-04 para minimizar dependencias entre cambios en `core/engine.py`.

1. **T-02 primero** — cambio de una línea en `auth.py`, arregla el test más visible (`TestExpiredJWT`).
2. **T-01** — fix en `scan_service.py` + parametrización en `n8n_client.py` + tests.
3. **T-03** — eliminar `UNKNOWN` en `engine.py` + test nuevo.
4. **T-04** — añadir timeout en `_run_ml_phase` + `configs/settings.py` + test nuevo.

Cada tarea termina con `pytest` sobre sus tests específicos antes de pasar a la siguiente.
