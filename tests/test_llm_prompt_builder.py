import json

from core.llm.prompt_builder import build_llm_prompt, extract_scan_summary


def test_extract_scan_summary_legacy_passthrough():
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
    # Contrato F4.2: bloque detector autoritativo + legacy passthrough
    assert "detector" in summary
    assert "evidences" in summary
    assert summary["legacy"]["label"] == "MALWARE"
    assert summary["legacy"]["score"] == 0.93
    assert "raw_bytes" not in json.dumps(summary)


def test_extract_scan_summary_detector_contract():
    scan = {
        "result": "suspicious",
        "risk_level": "high",
        "operational_status": "SUSPICIOUS",
        "confidence": 0.0,
        "degraded": False,
        "coverage": 1.0,
        "sha256": "abc123",
        "final_verdict": {"verdict": "suspicious", "risk_level": "critical",
                          "score": 0.29, "contradiction": "ML benign vs PE suspicious"},
        "correlation": {"score": 0.29, "verdict": "suspicious"},
        "evidences": [
            {"source": "ml_onnx", "verdict": "benign", "score_raw": 0.0,
             "score_norm": 0.0, "severity": "low", "reliability": "medium",
             "evidence_group": "ml_prob", "status": "ok",
             "indicators": [], "reasons": ["ml_score=0.0"]},
            {"source": "heuristic", "verdict": "malicious", "score_raw": 120.0,
             "score_norm": 1.0, "severity": "critical", "reliability": "medium",
             "evidence_group": "pe_heuristic", "status": "ok",
             "indicators": [{"name": "overlay_ratio=98%"}],
             "reasons": ["overlay_ratio=98.7% > 80%"]},
        ],
        "family_likelihoods": {"xworm": 6, "asyncrat": 11},
        "top_family": None,
    }
    summary = extract_scan_summary(scan)
    assert summary["detector"]["verdict"] == "suspicious"
    assert summary["detector"]["correlation_score"] == 0.29
    assert summary["detector"]["contradiction"] == "ML benign vs PE suspicious"
    assert len(summary["evidences"]) == 2
    assert summary["evidences"][1]["source"] == "heuristic"
    assert summary["evidences"][1]["score_raw"] == 120.0
    # Nunca inventar valores: score -1.0 ya no existe como default
    assert summary["detector"]["verdict"] != "unknown"


def test_build_llm_prompt_contains_guardrails_and_summary():
    scan = {"result": "benign", "risk_level": "low", "operational_status": "CLEAN",
            "confidence": 1.0, "degraded": False, "coverage": 1.0,
            "evidences": [], "final_verdict": {"verdict": "benign"}}
    prompt = build_llm_prompt(scan)
    assert "Tu tarea NO es detectar malware" in prompt
    assert "Responde SIEMPRE en formato JSON válido" in prompt
    assert "AUTORITATIVO" in prompt
    assert "Familia no determinada / no concluyente" in prompt
    assert "SCAN_SUMMARY" in prompt
    assert '"verdict": "benign"' in prompt
