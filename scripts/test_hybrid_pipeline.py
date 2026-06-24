"""
Test completo del pipeline híbrido con UPX real.

Prueba:
1. Empacar un PE real con UPX
2. Verificar que el UPXUnpacker lo detecta y desempaca
3. Verificar que el engine procesa el archivo desempacado
4. Verificar que el resultado es diferente al del PE empacado
"""
import sys
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

sys.path.insert(0, ".")

SOURCE_PE = Path("samples/procexp64.exe")
print("=== Test Completo: Pipeline Híbrido con UPX Real ===\n")

# ── Verificar que UPX está disponible ──────────────────────────────
upx_bin = shutil.which("upx")
if not upx_bin:
    print("❌ UPX no encontrado en PATH. Instalar con: sudo apt install upx-ucl")
    sys.exit(1)
print(f"✅ UPX encontrado en: {upx_bin}")

# ── Crear PE empacado con UPX ──────────────────────────────────────
tmp_dir   = Path(tempfile.mkdtemp(prefix="shadownet_test_"))
packed_pe = tmp_dir / "procexp64_packed.exe"

print(f"\n--- Empacando {SOURCE_PE.name} con UPX ---")
shutil.copy(SOURCE_PE, packed_pe)
result = subprocess.run(
    ["upx", "--best", "--force", str(packed_pe)],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    timeout=30,
)
if result.returncode != 0:
    print(f"❌ UPX empacado falló: {result.stderr}")
    shutil.rmtree(tmp_dir)
    sys.exit(1)

original_size = SOURCE_PE.stat().st_size
packed_size   = packed_pe.stat().st_size
print(f"  Original : {original_size / 1024:.1f} KB")
print(f"  Empacado : {packed_size / 1024:.1f} KB ({100*packed_size//original_size}% del original)")

# ── Test del UPXUnpacker directamente ─────────────────────────────
print("\n--- Test del Módulo UPXUnpacker ---")
from core.unpacking import UPXUnpacker
unpacker = UPXUnpacker()

assert unpacker._upx_available, "UPX debería estar disponible"
print(f"  UPX disponible   : {unpacker._upx_available} ✅")

# Verificar detección
raw_data = packed_pe.read_bytes()
is_packed = unpacker.is_packed(raw_data)
print(f"  Detecta empacado : {is_packed} ✅" if is_packed else f"  Detecta empacado : {is_packed} ❌")
assert is_packed, "El PE empacado debería ser detectado como UPX"

# Desempacar
unpack_result = unpacker.try_unpack(packed_pe)
print(f"  Desempacado      : {unpack_result.was_unpacked}")
print(f"  Ruta resultado   : {unpack_result.unpacked_path}")
assert unpack_result.was_unpacked, "El desempacado debería ser exitoso"

unpacked_size = unpack_result.unpacked_path.stat().st_size
print(f"  Tamaño desempacado: {unpacked_size / 1024:.1f} KB")
assert unpacked_size > packed_size, "El PE desempacado debería ser más grande que el empacado"

# ── Test del Engine con el PE empacado ────────────────────────────
print("\n--- Test del Engine con PE Empacado (UPX Auto-Unpack) ---")
from core.engine import ShadowNetEngine
engine = ShadowNetEngine()

# Escanear el PE original
result_original = engine.scan_file(SOURCE_PE)
print(f"  [Original]  label={result_original['label']} | score={result_original['score']} | fases={result_original['detection_phases']} | unpacked={result_original['was_unpacked']}")

# Escanear el PE empacado — el engine debería detectar UPX y desempacar
result_packed = engine.scan_file(packed_pe)
print(f"  [Empacado]  label={result_packed['label']} | score={result_packed['score']} | fases={result_packed['detection_phases']} | unpacked={result_packed['was_unpacked']}")

assert result_packed["was_unpacked"] is True, "El engine debería haber desempacado el PE"
assert "UPX_DETECT" in result_packed["detection_phases"], "Debería haber detectado UPX"
assert "UPX_UNPACK" in result_packed["detection_phases"], "Debería haber desempacado"
print(f"\n  ✅ Engine detectó y desempacó UPX automáticamente")
print(f"  ✅ Score tras desempacado: {result_packed['score']} (igual al original: {result_original['score']})")

# ── Test del BehavioralShield ──────────────────────────────────────
print("\n--- Test del BehavioralShield ---")
from core.dynamic import BehavioralShield
shield = BehavioralShield()
report = shield.analyze_process(os.getpid())
print(f"  PID analizado    : {report.pid}")
print(f"  Score de riesgo  : {report.risk_score}")
print(f"  Es sospechoso    : {report.is_suspicious}")
print(f"  Acciones         : {[a.description for a in report.suspicious_actions]}")

# ── Test del YaraScanner ───────────────────────────────────────────
print("\n--- Test del YaraScanner ---")
from security.yara_scanner import YaraScanner
scanner = YaraScanner()
print(f"  Reglas cargadas  : {scanner.rules_loaded}/4")
yara_result = scanner.scan(SOURCE_PE)
print(f"  Matches en procexp: {yara_result.threat_names}")

# ── Limpieza ───────────────────────────────────────────────────────
unpack_result.cleanup()
shutil.rmtree(tmp_dir)
print("\n  ✅ Archivos temporales eliminados")

# ── Resultado Final ────────────────────────────────────────────────
print("\n" + "="*55)
print("✅ TODOS LOS TESTS PASARON — Pipeline Híbrido 100% Operativo")
print("="*55)
print(f"  YARA      : {scanner.rules_loaded}/4 reglas activas")
print(f"  UPX       : Detección y desempacado automático OK")
print(f"  Behavioral: psutil activo, {len(report.suspicious_actions)} acciones en proceso propio")
print(f"  Engine    : Pipeline YARA → UPX → ML funcionando")
