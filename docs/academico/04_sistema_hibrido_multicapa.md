# Sistema Híbrido Multicapa — Diseño y Justificación

> Fuente: `core/engine.py`, `core/heuristics/`, `core/overlay/`,
> `core/dotnet/__init__.py`, `core/dotnet/il_analyzer.py`,
> `security/yara_scanner.py`. Auditado 2026-08-18.

---

## Motivación del diseño multicapa

Ninguna técnica individual de detección de malware cubre todos los vectores de evasión existentes:

| Técnica | Fortaleza | Vector de evasión |
|---------|-----------|-------------------|
| YARA (firmas) | Alta precisión en familias conocidas | Polimorfismo, modificación de bytes |
| ML estático | Generalización a variantes | Packing, cifrado, overlay |
| Overlay Analysis | Detecta payloads ocultos | Solo aplica a binarios PE con overlay |
| DotNet Analysis | Detecta ofuscación CLR | Solo aplica a ensamblados .NET |
| IL Behavioral | Evidencias forenses de comportamiento | Requiere acceso a tablas CLR |

La solución es componer estas técnicas en capas independientes donde cada una contribuye al `operational_status` final sin reemplazar a las demás.

---

## Capa 1 — ML Estático

**Implementación**: `models/inference.py` + `extractors/extractor.py`

Produce un **score continuo** en [0.0, 1.0] que representa la probabilidad de que el binario sea malware según los patrones aprendidos sobre 5.1M muestras.

**Fortaleza**: Generalización estadística a variantes no vistas del mismo patrón.

**Limitación confirmada en campo**: El modelo asignó score=0.0000 a `sample1.exe` a pesar de que el archivo tiene 98.7% de su contenido en un overlay de alta entropía. El extractor opera sobre la estructura PE declarada; el overlay no contribuye significativamente al vector de features porque el muestreo distribuido en archivos grandes puede no capturar su contenido, y la estructura PE en sí puede ser perfectamente legítima.

**Output del motor**: `label` ∈ {BENIGN, MALWARE} y `score` ∈ [0.0, 1.0].

---

## Capa 2 — YARA

**Implementación**: `security/yara_scanner.py`

Opera sobre el binario completo (bytes raw) con reglas de firma deterministas.
4 archivos de reglas activos: trojans, spyware, worms, ransomware.

**Prioridad**: Si hay match, el resultado es inmediatamente `DANGEROUS` sin ejecutar fases posteriores (cortocircuito en el pipeline).

**Limitación**: Las reglas YARA son estáticas. Sin actualización periódica no detectan malware nuevo sin firma conocida.

**Falso positivo documentado**: `procexp64.exe` (Sysinternals) activa `Keylogger_Generic`.

---

## Capa 3 — Overlay Analysis

**Implementación**: `core/overlay/analyzer.py` (referenciado desde `core/engine.py`)

Analiza los bytes del archivo que se encuentran **después del último byte del PE** según la estructura de secciones declarada en el header.

**Indicadores calculados**:

| Indicador | Descripción | Umbral CRITICAL |
|-----------|-------------|-----------------|
| `overlay_ratio` | Fracción del archivo en overlay | > 93% |
| `overlay_entropy` | Entropía de Shannon del overlay | > 7.8 |
| `global_entropy` | Entropía global del binario | > 7.5 |
| `embedded_pe_detected` | Presencia de magic bytes MZ en overlay | Cualquier caso |
| `is_known_installer` | NSIS / InnoSetup detectado | Reduce score (benign) |

**Resultado en sample1.exe** (ejecución real 2026-08-18):
```
overlay_present:     True
overlay_ratio:       0.9869  (98.7%)
overlay_entropy:     7.9987
global_entropy:      7.9861
embedded_pe_count:   0
is_known_installer:  False
risk_score:          105
risk_level:          CRITICAL
operational_status:  DANGEROUS
```

La capa de Overlay Analysis detectó correctamente la anomalía que el modelo ML no pudo capturar.

---

## Capa 4 — DotNet Analysis

**Implementación**: `core/dotnet/__init__.py`

Activada únicamente si el binario contiene un CLR header (es un ensamblado .NET).

**Componentes**:

- `DotNetAssemblyInfo`: versión CLR, strong name, IL-only vs Mixed mode
- `DotNetObfuscatorInfo`: detecta ConfuserEx, Dotfuscator, SmartAssembly mediante 3 heurísticas (strings heap, metadata patterns, resources)
- `DotNetEmbeddedInfo`: detecta assemblies/PEs embebidos en recursos del assembly
- `DotNetSuspiciousILInfo`: detecta Reflection, P/Invoke dinámico, LoadLibrary en IL
- `DotNetRiskProfile`: score 0–100 con pesos: obfuscation=20, embedded_PE=35, IL_sospechoso=8–20

**Resultado en sample2.exe** (ejecución real 2026-08-18):
```
is_dotnet:              True
obfuscator_detected:    True
obfuscator_name:        Unknown Obfuscator
dotnet_risk_score:      28
dotnet_risk_level:      MEDIUM
il_score:               8
operational_status:     CLEAN  (score insuficiente para elevar)
```

---

## Capa 5 — IL Behavioral Analysis

**Implementación**: `core/dotnet/il_analyzer.py`

Extrae tokens de las tablas de metadatos CLR del binario sin ejecutarlo (análisis estático de IL):

**Tablas parseadas**: `#Strings`, `#US` (User Strings), `MemberRef`, `TypeRef`, `AssemblyRef`, `ModuleRef`/PInvoke.

**Categorías de comportamiento y tests verificados**:

| ID | Categoría | Tests que lo validan |
|----|-----------|----------------------|
| M2 | Reflection | `test_reflection_detected`, `test_reflection_not_detected_in_legit` |
| M3 | Dynamic Loading | `test_dynamic_loading_detected` |
| M5 | Injection | `test_injection_detected`, `test_injection_not_in_legit` |
| M6 | Persistence | `test_persistence_registry` |
| M7 | Networking | `test_networking_detected`, `test_networking_legit_not_flagged` |
| M8 | Command Execution | `test_cmd_exec_detected` |
| M9 | Credential Theft | `test_credential_theft_chrome`, `test_credential_theft_firefox` |
| M10 | Worm | `test_worm_detected` |
| — | Stealer | `test_stealer_discord`, `test_stealer_crypto_wallet` |
| — | RAT | `test_rat_keylogger`, `test_rat_screen_capture` |

Todos los tests anteriores: **PASSED** (suite 2026-08-18).

**Familias identificadas** (con tests verificados):
- XWorm: `test_xworm_family_top` → PASSED
- AgentTesla: `test_agenttesla_family_top` → PASSED

**Evidencias forenses producidas por cada indicador**:
```json
{
  "source": "MemberRef",
  "value": "VirtualAlloc",
  "location": "offset: 0x1A40",
  "confidence": "high"
}
```

---

## Capa 6 — Risk Engine

**Implementación**: `core/heuristics/` (referenciado en `core/engine.py`)

La capa de mayor nivel semántico. Recibe los outputs de todas las capas anteriores y produce un veredicto **ortogonal** al del modelo ML.

**Lógica de correlación** (verificada en tests):

```
test_ml_malware_always_dangerous        → PASSED: ML=malware → siempre DANGEROUS
test_ml_benign_critical_heuristic_is_dangerous → PASSED: ML=benign + heurística CRITICAL → DANGEROUS
test_ml_benign_medium_heuristic_is_suspicious  → PASSED: ML=benign + heurística MEDIUM → SUSPICIOUS
test_dropper_scores_critical            → PASSED: dropper pattern → CRITICAL
test_yara_overlay_hit_raises_score      → PASSED: YARA en overlay → eleva score
test_installer_gets_discount            → PASSED: NSIS/InnoSetup → reduce score
test_no_imports_raises_score            → PASSED: sin imports → eleva score
```

**El campo `operational_status` puede divergir del `label` ML**. Esta es la característica definitoria de la arquitectura multicapa. El Risk Engine puede declarar `DANGEROUS` sobre un binario que el ML etiqueta como `BENIGN` cuando las capas heurísticas presentan indicadores de riesgo críticos.

---

## Justificación del diseño multicapa

El sistema es multicapa porque:

1. **Cobertura ortogonal**: cada capa detecta vectores de ataque que las otras no cubren. La Overlay Analysis detecta lo que el ML no ve. El IL Behavioral detecta comportamiento sin ejecutar el código.

2. **Independencia de fallos**: si una capa falla (test `test_phase_failure_continues` → PASSED), el pipeline continúa con las fases restantes. No hay single point of failure.

3. **Evidencias auditables**: el sistema no solo produce un veredicto, sino una cadena de evidencias (overlay ratio, triggered indicators, IL tokens, YARA rules) que un analista puede verificar.

4. **Reducción de evasión**: para evadir el sistema completo, un atacante debe simultáneamente: no tener firma YARA, tener features similares a benignos, no tener overlay de alta entropía, no contener código IL sospechoso, y no activar indicadores heurísticos. La conjunción de todas estas condiciones es significativamente más difícil que evadir cualquiera de ellas individualmente.

---

## Estado de integración en `scan_file()` (auditado)

```
engine.scan_file(path)
  → _phase_yara(path)          ✅ integrado
  → _extract_features(path)    ✅ integrado
  → _phase_ml(features)        ✅ integrado
  → _phase_overlay(path)       ✅ integrado
  → _phase_dotnet(path)        ✅ integrado
  → _phase_il(path)            ✅ integrado (si is_dotnet)
  → _phase_risk(all_outputs)   ✅ integrado
  → BehavioralShield           ❌ NO integrado (código en core/dynamic/ no conectado)
```
