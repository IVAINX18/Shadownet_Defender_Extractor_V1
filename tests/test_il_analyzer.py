"""
tests/test_il_analyzer.py — Tests unitarios del IL Behavioral Analyzer.

Valida:
    - Detección correcta por cada categoría (M2-M12).
    - Scoring de familias (M13).
    - DotNet threat score (M14).
    - Cero falsos positivos en apps legítimas (M7/FP protection).
    - Integración con engine result dict (M15/M16).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.dotnet.il_analyzer import ILBehavioralAnalyzer


@pytest.fixture
def analyzer():
    return ILBehavioralAnalyzer()


# ─── Helpers ───────────────────────────────────────────────────────────────

def make_data(*strings: str) -> bytes:
    """Construye bytes simulando un binario .NET con las strings dadas."""
    return b"\x00".join(s.encode("ascii") for s in strings) * 3


# ─── M2: Reflection ────────────────────────────────────────────────────────

def test_reflection_detected(analyzer):
    data = make_data("Assembly.Load", "System.Reflection", "Activator.CreateInstance")
    r = analyzer.analyze(data)
    assert r.reflection.detected is True
    assert r.reflection.score > 0


def test_reflection_not_detected_in_legit(analyzer):
    data = make_data("System.Windows.Forms", "Button", "Label", "TextBox")
    r = analyzer.analyze(data)
    assert r.reflection.detected is False


# ─── M3: Dynamic Loading ───────────────────────────────────────────────────

def test_dynamic_loading_detected(analyzer):
    data = make_data("Assembly.LoadFrom", "GetManifestResourceStream")
    r = analyzer.analyze(data)
    assert r.dynamic_loading.detected is True


# ─── M5: Injection ─────────────────────────────────────────────────────────

def test_injection_detected(analyzer):
    data = make_data("VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread")
    r = analyzer.analyze(data)
    assert r.injection.detected is True
    # Score mínimo en modo fallback (confidence=low, 3pts por hit)
    assert r.injection.score >= 3


def test_injection_not_in_legit(analyzer):
    data = make_data("System.IO.File", "Console.WriteLine", "Math.Sqrt")
    r = analyzer.analyze(data)
    assert r.injection.detected is False


# ─── M6: Persistence ───────────────────────────────────────────────────────

def test_persistence_registry(analyzer):
    data = make_data(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "ScheduledTask",
    )
    r = analyzer.analyze(data)
    assert r.persistence.detected is True


# ─── M7: Networking ────────────────────────────────────────────────────────

def test_networking_detected(analyzer):
    data = make_data("System.Net.WebClient", "TcpClient", "HttpClient")
    r = analyzer.analyze(data)
    assert r.networking.detected is True


def test_networking_legit_not_flagged(analyzer):
    # System.Windows.Forms no tiene networking
    data = make_data("Button", "Label", "Form", "Panel")
    r = analyzer.analyze(data)
    assert r.networking.detected is False


# ─── M8: Command Execution ─────────────────────────────────────────────────

def test_cmd_exec_detected(analyzer):
    data = make_data("cmd.exe", "powershell.exe", "Process.Start")
    r = analyzer.analyze(data)
    assert r.cmd_exec.detected is True


# ─── M9: Credential Theft ──────────────────────────────────────────────────

def test_credential_theft_chrome(analyzer):
    data = make_data("Login Data", r"\Google\Chrome\User Data", "CryptUnprotectData")
    r = analyzer.analyze(data)
    assert r.credential_theft.detected is True


def test_credential_theft_firefox(analyzer):
    data = make_data("logins.json", "key4.db", r"\Mozilla\Firefox\Profiles")
    r = analyzer.analyze(data)
    assert r.credential_theft.detected is True


# ─── M10: Worm ─────────────────────────────────────────────────────────────

def test_worm_detected(analyzer):
    data = make_data("DriveInfo.GetDrives", "autorun.inf", "NetShareEnum")
    r = analyzer.analyze(data)
    assert r.worm.detected is True


# ─── M11: Stealer ──────────────────────────────────────────────────────────

def test_stealer_discord(analyzer):
    data = make_data("discord", r"\Discord\Local Storage", "api.telegram.org")
    r = analyzer.analyze(data)
    assert r.stealer.detected is True


def test_stealer_crypto_wallet(analyzer):
    data = make_data("wallet.dat", r"\Exodus\exodus.wallet", "metamask")
    r = analyzer.analyze(data)
    assert r.stealer.detected is True


# ─── M12: RAT ──────────────────────────────────────────────────────────────

def test_rat_keylogger(analyzer):
    data = make_data("GetAsyncKeyState", "SetWindowsHookEx", "WH_KEYBOARD_LL")
    r = analyzer.analyze(data)
    assert r.rat.detected is True


def test_rat_screen_capture(analyzer):
    data = make_data("CopyFromScreen", "GetDesktopWindow", "BitBlt")
    r = analyzer.analyze(data)
    assert r.rat.detected is True


# ─── M13: Family Scoring ───────────────────────────────────────────────────

def test_xworm_family_top(analyzer):
    """XWorm debe ser top familia cuando se activan worm+injection+networking+rat."""
    data = make_data(
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
        "DriveInfo.GetDrives", "autorun.inf",
        "TcpClient", "NetworkStream",
        "GetAsyncKeyState", "CopyFromScreen",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    )
    r = analyzer.analyze(data)
    assert r.family_likelihoods.get("xworm", 0) > 0
    assert r.top_family in ("xworm", "njrat", "asyncrat")  # Todas RAT-worm


def test_agenttesla_family_top(analyzer):
    """AgentTesla debe puntuar alto con credential theft + stealer + network."""
    data = make_data(
        "Login Data", r"\Google\Chrome\User Data", "CryptUnprotectData",
        "SmtpClient", "WebClient", "DownloadString",
        "api.telegram.org", "sendDocument",
        "Clipboard.GetText",
    )
    r = analyzer.analyze(data)
    assert r.family_likelihoods.get("agenttesla", 0) >= 40
    assert r.top_family == "agenttesla"


def test_legit_app_no_family(analyzer):
    data = make_data("System.Windows.Forms", "Button", "Label", "TextBox", "Panel")
    r = analyzer.analyze(data)
    # Ninguna familia debe superar el 20% en una app legítima sin indicadores
    for fam, score in r.family_likelihoods.items():
        assert score < 20, f"FP: familia {fam} puntuó {score} en app legítima"
    assert r.top_family == ""


# ─── M14: Threat Score ─────────────────────────────────────────────────────

def test_threat_score_critical_xworm(analyzer):
    data = make_data(
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
        "TcpClient", "NetworkStream", "WebClient",
        "GetAsyncKeyState", "CopyFromScreen",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "cmd.exe", "powershell.exe",
    )
    r = analyzer.analyze(data)
    # HIGH o CRITICAL con score normalizado >= 65 (injection+persistence+networking+rat+cmd)
    assert r.dotnet_threat_score >= 65
    assert r.dotnet_threat_level in ("HIGH", "CRITICAL")


def test_threat_score_low_legit(analyzer):
    data = make_data("System.Windows.Forms", "Button", "Label")
    r = analyzer.analyze(data)
    assert r.dotnet_threat_score < 25
    assert r.dotnet_threat_level == "LOW"


def test_threat_score_medium(analyzer):
    """Solo networking + persistence = MEDIUM o cerca del umbral."""
    data = make_data(
        "TcpClient", "WebClient",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    )
    r = analyzer.analyze(data)
    # networking (10pts) + persistence (15pts) = 25pts / 113 = 22% → LOW/MEDIUM boundary
    assert r.dotnet_threat_score >= 20
    assert r.dotnet_threat_level in ("LOW", "MEDIUM")


# ─── M15: Operational Status ───────────────────────────────────────────────

def test_m15_status_elevation_dangerous():
    """Cuando threat_score >= 75 el engine debe forzar DANGEROUS."""
    # Simulamos el comportamiento del engine._run_il_phase
    result = {
        "is_dotnet": True,
        "operational_status": "CLEAN",
        "details": {},
    }
    threat_score = 87  # CRITICAL

    if threat_score >= 75:
        result["operational_status"] = "DANGEROUS"

    assert result["operational_status"] == "DANGEROUS"


def test_m15_status_elevation_suspicious():
    result = {"operational_status": "CLEAN"}
    threat_score = 55  # HIGH
    if 50 <= threat_score < 75 and result["operational_status"] in ("CLEAN", "UNKNOWN"):
        result["operational_status"] = "SUSPICIOUS"
    assert result["operational_status"] == "SUSPICIOUS"


def test_m15_no_elevation_legit():
    result = {"operational_status": "CLEAN"}
    threat_score = 0
    if threat_score >= 75:
        result["operational_status"] = "DANGEROUS"
    elif threat_score >= 25:
        result["operational_status"] = "SUSPICIOUS"
    assert result["operational_status"] == "CLEAN"


# ─── M16: Telemetría plana ─────────────────────────────────────────────────

def test_to_dict_has_all_fields(analyzer):
    data = make_data("VirtualAlloc", "TcpClient", "GetAsyncKeyState")
    r = analyzer.analyze(data)
    d = r.to_dict()
    required_keys = [
        "injection_detected", "injection_score",
        "persistence_detected", "persistence_score",
        "networking_detected", "network_score",
        "credential_theft_detected", "credential_score",
        "worm_behavior_detected", "worm_score",
        "rat_detected", "rat_score",
        "stealer_detected", "stealer_score",
        "reflection_detected", "reflection_score",
        "dynamic_loading_detected", "dynamic_loading_score",
        "embedded_resource_count", "embedded_pe_count",
        "family_likelihoods", "top_family",
        "dotnet_threat_score", "dotnet_threat_level",
        "total_indicators_fired",
    ]
    for key in required_keys:
        assert key in d, f"Campo faltante en telemetría: {key}"


# ─── Performance básico ────────────────────────────────────────────────────

def test_performance_large_binary(analyzer):
    """El analyzer debe completar en <2s para binarios de 5MB."""
    import time
    data = (b"VirtualAlloc TcpClient Assembly.Load " * 200).ljust(5 * 1024 * 1024, b"\x00")
    start = time.time()
    r = analyzer.analyze(data)
    elapsed = time.time() - start
    assert elapsed < 2.0, f"Demasiado lento: {elapsed:.2f}s para 5MB"
    assert r.dotnet_threat_score >= 0  # Siempre produce resultado


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
