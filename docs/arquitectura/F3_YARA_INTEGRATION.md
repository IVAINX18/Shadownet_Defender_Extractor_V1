# F3 — YARA Integration

**Estado:** IMPLEMENTED
**Fecha:** 2026-09-06
**Dependencia:** `yara-python>=4.3.0` (`requirements/base.in`), instalado `4.5.2` en `.venv` Python 3.11.14

## Arquitectura
```
YARA Engine (security/yara_scanner.py) → YARA Evidence (core/evidence.yara_evidence) → Evidence Contract → CorrelationEngine → Verdict/Risk/Operational
```
YARA es fuente estática, no decide sola salvo veto determinista.

## Reglas
Ubicación: `security/yara_rules/` (4 archivos, 15 reglas): `trojans.yar` (4), `spyware.yar` (4), `ransomware.yar` (4), `worms.yar` (3). Cada regla `meta: author, description, severity (critical/high/medium), category`. Baseline auditable, no 100s de reglas externas. Compilación tolerante: `_load_rules()` compila por archivo, `failed` se loggea pero no bloquea motor; `is_available` requiere ≥1 válido.

## Evidence Contract
`yara_evidence(has_matches, matches, threat_names, status)`:
- `has_matches + severity critical/high` → `MALICIOUS/CRITICAL/DANGEROUS/DETERMINISTIC 1.0`
- `medium` → `SUSPICIOUS/HIGH/SUSPICIOUS/HIGH 0.85`
- `no match` → `BENIGN/LOW/CLEAN/MEDIUM`
- `UNAVAILABLE` (import falla / 0 reglas) → `UNKNOWN/LOW/UNKNOWN`, `score None`
- `DEGRADED` (timeout 30s) → `UNKNOWN/DEGRADED`, nunca `BENIGN`
- `ERROR` (SyntaxError) → `UNKNOWN/DEGRADED`

`evidence_group=yara_sig`, `reliability_weight` por severidad, `indicators` con `rule/meta`, `reasons` con `yara_match: <rule>`, `metadata` con `threat_names/match_count/severities`.

Preserva `rule`, `category`, `tags`, `meta` para forense; no almacena bytes completos.

## Scanner
`YaraScanner(rules_dir=security/yara_rules)`:
- `yara.compile(filepaths=valid_dict)` tras validar cada `.yar` individualmente.
- `scan(file_path)` y `scan_bytes(data, label)` con `timeout=30`.
- `TimeoutError → error="YARA timeout (30s)"` → `DEGRADED`; `SyntaxError → UNAVAILABLE`; otros `Exception → UNAVAILABLE` nunca `BENIGN`.
- `_parse_match` extrae `meta/severity/category`.

`core/engine.py:369-448` `_run_yara_phase`: maneja `whitelist.json` (hash + `yara_exclusions`), propaga `yara_degraded` en `result["details"]["yara_degraded"]`, incluye `meta` en `yara_matches`, `DEGRADED` vía `_run_correlation_phase:965-970`.

## Correlation
`core/correlation.py:192-214` veto YARA: `yara.status OK + verdict MALICIOUS → MALICIOUS/CRITICAL/DANGEROUS` sin promediar. `yara_sig` grupo aislado, `w=1.0` DETERMINISTIC, no double-count con `pe_heuristic`. `UNAVAILABLE/DEGRADED` ignorado en `S`, `coverage` refleja disponibilidad.

## Health
`backend/app/api/routes/health.py:48-58` `_check_yara()` → `available/unavailable`; `_compute_pipeline_mode` → `full` si `onnx loaded + yara available`, `503` si crítico degradado.

## Timeout / Robustez
`yara.TimeoutError`, `SyntaxError`, `OSError`, `FileNotFoundError`, `PermissionError` capturados, loggeados, retornan `UNAVAILABLE/DEGRADED`, nunca `BENIGN` silencioso. Límite tamaño vía `engine` `MAX_UPLOAD_MB 200` y `read_bytes` ya existente; YARA usa filepath (no duplica límite).

## Testing
`tests/fixtures/yara/test_only.yar` (2 TEST_ONLY reglas high/medium), `tests/test_yara_integration.py` 10 tests: disponible+no-match, malicious veto, unavailable, compilación, timeout, múltiples matches, contradicción, no-match+PE, unavailable+PE, ruleset inválido. Todos `Evidence Contract` puro, fixtures sintéticos, nunca ejecutan malware.

## Seguridad
Solo lectura bytes, hashes, YARA match; nunca `exec`/`sample2.exe` execution; no secretos en logs; `sample2.exe` solo estático.

## Limitaciones
Reglas baseline pequeñas; falsos positivos posibles en genéricas `medium`; futuras reglas deben añadir `severity` y test `TEST_ONLY`.
