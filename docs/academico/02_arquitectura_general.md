# Arquitectura General — ShadowNet Defender

> Derivado de auditoría directa de `core/engine.py`, `backend/app/main.py`,
> `models/inference.py`, `security/yara_scanner.py`, `core/dotnet/`,
> `core/heuristics/`, `core/integrations/`. Ejecutado 2026-08-18.

---

## Pipeline de análisis de archivos

```mermaid
flowchart TD
    A[CLI / API REST] --> B[Validación entrada\nsha256, tamaño, extensión]
    B --> C[YARA Scanner\n4 archivos de reglas]
    C -->|match| D[DANGEROUS inmediato]
    C -->|no match| E[Feature Extractor\n2381 dims]
    E --> F[UPX / Packer Detection\nentropía, ratio secciones]
    F --> G[ML Inference\nONNX Runtime\n2381→512→256→128→1]
    G --> H[Overlay Analysis\nentropía, embedded PE\nYARA overlay]
    H --> I[DotNet Analysis\nCLR header, ofuscadores\nassemblies embebidos]
    I --> J[IL Behavioral Analysis\ntokens CLR M2-M15]
    J --> K[Risk Engine\ncorrelación multicapa]
    K --> L[ScanResult\nlabel score operational_status\nrisk_level risk_score evidencias]
    L --> M[Backend FastAPI]
    M --> N[Supabase\npersistencia]
    M --> O[n8n\nalertas webhook]
    M --> P[LLM cloud Groq/Gemini + Template (cascada Tri-Fallover)\nexplicación en lenguaje natural]
```

---

## Componentes del pipeline (detalle)

### CLI

Punto de entrada para análisis de archivos individuales o por lotes.
Produce output JSON con todos los campos del `ScanResult`.

### Feature Extractor (`extractors/extractor.py`)

Convierte un binario PE a un vector de **2381 dimensiones** mediante 8 bloques:

| Bloque | Dimensiones | Descripción |
|--------|-------------|-------------|
| ByteHistogram | 256 | Frecuencia relativa de cada byte 0x00-0xFF |
| ByteEntropy | 256 | Entropía de Shannon en ventanas deslizantes |
| Strings | 104 | IoCs extraídos: URLs, APIs Win32, registry keys, comandos |
| General | 10 | Metadatos: tamaño, nº imports, nº exports, etc. |
| Header | 62 | Cabeceras PE: timestamps, flags, subsystem, magic |
| Section | 255 | Análisis de secciones: entropía, RWX, discrepancias virtual/raw |
| Imports | 1280 | Feature hashing SHA-256 de APIs importadas (IAT) |
| Exports | 128 | Feature hashing de símbolos exportados |

Archivo >10 MB: muestreo distribuido (inicio + centro + fin). Si `pefile` falla: modo `RAW_FALLBACK`.

### YARA Scanner (`security/yara_scanner.py` — Fase 1)

Escaneo determinista. Si hay coincidencia: resultado inmediato `DANGEROUS`, score=1.0, sin ejecutar fases posteriores.
4 archivos de reglas cargados en tiempo de inicio.

### UPX / Packer Detection (integrado en Extractor)

Indicadores en el vector de features:
- `is_packed_upx`: detecta sección `.UPX0`/`.UPX1`
- `high_entropy_sections`: entropía por sección > umbral
- `global_entropy`: entropía global del binario
- `ratio_virtual_real`: ratio tamaño virtual/real de secciones

### ML / ONNX (`models/inference.py` — Fase 3)

Red neuronal fully connected:
```
Input (2381) → BatchNorm + ReLU + Dropout(0.3) → 512
            → BatchNorm + ReLU + Dropout(0.2) → 256
            → BatchNorm + ReLU + Dropout(0.1) → 128
            → Sigmoid → Output (1, rango 0.0–1.0)
```
- Umbral engine: 0.5 (≥0.5 → MALWARE)
- Umbral tripartito backend: <0.4 benign / 0.4–0.7 suspicious / >0.7 malicious
- Preprocesamiento: `StandardScaler` Z-score (`scaler.pkl`)
- Formato exportado: ONNX Opset 11

### Overlay Analysis (`core/overlay/` — Fase 4)

Analiza datos ubicados después del último byte del PE declarado:
- `overlay_ratio`: fracción del archivo en overlay
- `overlay_entropy`: entropía del overlay
- `embedded_pe_detected`: busca magic bytes MZ en overlay
- `is_known_installer`: detecta NSIS, InnoSetup (reduce falsos positivos)
- YARA sobre overlay

### DotNet Analysis (`core/dotnet/__init__.py` — Fase 5)

Si el binario es un ensamblado CLR:
- Detecta ofuscadores: ConfuserEx, Dotfuscator, SmartAssembly
- Detecta assemblies embebidos en recursos
- Detecta IL sospechoso: Reflection, P/Invoke dinámico, LoadLibrary
- Produce `dotnet_risk_score` (0–100) y `dotnet_risk_level`

### IL Behavioral Analysis (`core/dotnet/il_analyzer.py` — Fase 6)

Extrae tokens de tablas CLR reales (`#Strings`, `#US`, `MemberRef`, `TypeRef`, `AssemblyRef`, `ModuleRef`/PInvoke):

| Categoría | Código | Indicadores |
|-----------|--------|-------------|
| Reflection | M2 | Assembly.Load, Activator, Type.GetType, InvokeMember |
| Dynamic Loading | M3 | Assembly.LoadFrom, BinaryFormatter, ResourceManager |
| Injection | M5 | VirtualAlloc, WriteProcessMemory, CreateRemoteThread, NtQueueApcThread |
| Persistence | M6 | Registry Run, ScheduledTask, WMI, Service |
| Networking | M7 | TCP, HTTP, WebClient, DNS, SMTP |
| Command Exec | M8 | cmd.exe, powershell, rundll32, Process.Start |
| Credential Theft | M9 | Chrome/Firefox/Edge logins, DPAPI, CredentialManager |
| Worm | M10 | DriveInfo, Removable media |

Cada indicador produce evidencias forenses: `source`, `value`, `location`, `confidence`.

### Risk Engine (`core/heuristics/` — Fase 7)

Correlaciona todos los outputs anteriores:

```
operational_status = f(
    yara_match,
    overlay_ratio + overlay_entropy,
    embedded_pe_detected,
    dotnet_risk_score,
    il_threat_score,
    ml_score,
    packer_detected
)
```

Salida: `operational_status` ∈ {CLEAN, SUSPICIOUS, DANGEROUS}
No modifica `label` ni `score` del ML. Opera de forma ortogonal.

---

## Arquitectura backend

```mermaid
flowchart LR
    Client -->|JWT| FastAPI
    FastAPI --> scan_service
    FastAPI --> llm_service
    FastAPI --> quarantine
    FastAPI --> remediation
    scan_service --> Engine
    scan_service --> Supabase
    scan_service --> n8n
    llm_service --> GroqClient/GeminiClient/TemplateExplainer (SDK openai)
    quarantine --> QuarantineManager
    remediation --> RemediationEngine
```

### Endpoints principales (verificados en `backend/app/api/routes/`)

| Método | Ruta | Función |
|--------|------|---------|
| POST | /scan/upload-explain | Sube archivo, ejecuta pipeline + LLM |
| POST | /scan/batch | Análisis por lotes |
| POST | /llm/explain | Explicación LLM de resultado existente |
| GET | /health | Estado de todos los componentes |
| POST | /quarantine/file | Aisla archivo malicioso |
| POST | /remediation/terminate | Termina proceso por PID |

---

## Integración Supabase

- Autenticación: JWT Bearer
- Tabla: `scan_results`
- Deduplicación: mismo SHA-256 en ventana de 60 segundos → descartado
- Tabla `incidents`: creada solo cuando `operational_status == "DANGEROUS"`
- Fallback offline: cola JSON en disco cuando Supabase no disponible

## Integración n8n

- Webhook activo únicamente para `result == "malicious"` (label ML)
- **Limitación documentada**: no se activa para `operational_status == "DANGEROUS"` con `label == "BENIGN"` (ver H-01)
- Payload: JSON con `safe_json()` aplicado

---

## Estado de implementación (auditado)

| Componente | Estado |
|------------|--------|
| YARA Scanner | ✅ Completo e integrado |
| Feature Extractor 2381 dims | ✅ Completo e integrado |
| ML/ONNX Inference | ✅ Completo e integrado |
| Overlay Analysis | ✅ Completo e integrado |
| DotNet/CLR Analysis | ✅ Completo e integrado |
| IL Behavioral Analysis | ✅ Completo e integrado |
| Risk Engine | ✅ Completo e integrado |
| Quarantine Manager | ✅ Completo e integrado |
| Remediation Engine | ✅ Completo e integrado |
| BehavioralShield (psutil) | ⚠️ Código existe, NO integrado al pipeline |
| n8n alertas por operational_status | ⚠️ Solo alerta por label ML, no por heurística |
| Supabase campos IL/overlay completos | ⚠️ Parcial |
