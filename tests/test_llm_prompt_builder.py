import json

from core.llm.prompt_builder import build_llm_prompt, extract_scan_summary


def test_extract_scan_summary_only_allowed_fields():
    scan = {
        "label": "MALWARE",
        "score": 0.93,
        "confidence": "High",
        "details": {
            "entropy": 7.2,
            "suspicious_imports": ["VirtualAlloc", "WriteProcessMemory"],
            "suspicious_sections": [".text", ".rwx"],
            "top_features": [{"name": "imports_hash_10", "value": 0.8, "impact": "high"}],
            "raw_bytes": "should_not_be_in_summary",
        },
    }
    summary = extract_scan_summary(scan)
    assert summary["label"] == "MALWARE"
    assert summary["score"] == 0.93
    assert "raw_bytes" not in summary


def test_build_llm_prompt_contains_guardrails_and_summary():
    scan = {"label": "BENIGN", "score": 0.02, "confidence": "High", "details": {}}
    prompt = build_llm_prompt(scan)
    assert "Tu tarea NO es detectar malware" in prompt
    assert "Responde SOLO en JSON válido" in prompt
    assert "SCAN_SUMMARY" in prompt
    # Debe incluir el bloque en JSON serializado
    assert '"label": "BENIGN"' in prompt
