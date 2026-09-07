"""
F4.2 — E2E Remediation tests.

Supabase: analysis_type legacy, adaptive PGRST204 strip, JWT propagation,
RLS/auth classification, transient vs permanent, dedup 23505, JSONB F4.
LLM (casos A-G): contrato actual, no contradiccion, familia no concluyente,
provider caido, respuesta contradictoria normalizada.
"""
from unittest.mock import MagicMock, patch

from core.llm.explanation_service import (
    ExplanationService,
    _normalize_llm_response,
    _validate_llm_response,
)
from core.llm.prompt_builder import build_llm_prompt, extract_scan_summary
from core.llm.template_explainer import TemplateExplainer


def _suspicious_scan():
    return {
        "file_name": "sample1.exe",
        "result": "suspicious",
        "risk_level": "high",
        "operational_status": "SUSPICIOUS",
        "confidence": 0.0,
        "degraded": False,
        "coverage": 1.0,
        "sha256": "f42-e2e-remediation-unique-sha256",
        "user_id": "f42-test-user",
        "user_email": "f42@test.local",
        "analysis_type": "pe",
        "final_verdict": {
            "verdict": "suspicious",
            "risk_level": "critical",
            "operational_status": "suspicious",
            "score": 0.29,
            "contradiction": "ML benign 0.00 contradicted by heuristic",
            "contributing_sources": ["heuristic", "overlay"],
        },
        "correlation": {"verdict": "suspicious", "score": 0.29},
        "evidences": [
            {"source": "ml_onnx", "verdict": "benign", "score_raw": 0.0,
             "score_norm": 0.0, "severity": "low", "reliability": "medium",
             "evidence_group": "ml_prob", "status": "ok",
             "indicators": [], "reasons": ["ml_score=0.0000"]},
            {"source": "heuristic", "verdict": "malicious", "score_raw": 120.0,
             "score_norm": 1.0, "severity": "critical", "reliability": "medium",
             "evidence_group": "pe_heuristic", "status": "ok",
             "indicators": [{"name": "overlay_ratio=98.7% > 80%"}],
             "reasons": ["overlay_ratio=98.7% > 80%", "overlay_entropy=7.99 > 7.8"]},
        ],
        "family_likelihoods": {"xworm": 6, "asyncrat": 11},
        "top_family": None,
    }


# ---------------------------------------------------------------------------
# Supabase
# ---------------------------------------------------------------------------

def test_analysis_type_kept_in_dto_but_stripped_if_remote_missing():
    """analysis_type es viva en DTO; si el remoto no la tiene, adaptive strip la excluye sin PGRST204."""
    from backend.app.integrations import supabase_client as sc

    assert "analysis_type" in sc.KNOWN_COLUMNS  # viva en modelo base + DTO AnalysisType
    record = {"file_name": "a.exe", "result": "benign", "analysis_type": "pe",
              "user_id": "u1", "sha256": "s1"}
    mock_client = MagicMock()
    # Primera llamada falla con PGRST204 nombrando analysis_type, segunda OK
    mock_client.table.return_value.insert.return_value.execute.side_effect = [
        Exception("Could not find the 'analysis_type' column of 'scan_results' in the schema cache (PGRST204)"),
        MagicMock(data=[{"id": "1"}]),
    ]
    out = sc._insert_adaptive(mock_client, record)
    assert out["stripped_columns"] == ["analysis_type"]
    second_payload = mock_client.table.return_value.insert.call_args_list[1][0][0]
    assert "analysis_type" not in second_payload
    assert second_payload["file_name"] == "a.exe"


def test_adaptive_strip_multiple_missing_f4_columns():
    from backend.app.integrations import supabase_client as sc

    record = {"file_name": "a.exe", "evidences": [], "final_verdict": {},
              "correlation": {}, "user_id": "u1"}
    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.side_effect = [
        Exception("Could not find the 'evidences' column (PGRST204)"),
        Exception("Could not find the 'final_verdict' column (PGRST204)"),
        MagicMock(data=[{"id": "1"}]),
    ]
    out = sc._insert_adaptive(mock_client, record)
    assert out["stripped_columns"] == ["evidences", "final_verdict"]


def test_save_scan_uses_service_client_with_jwt_user():
    """Opcion B: con service key, el service client persiste con user_id del JWT."""
    from backend.app.integrations import supabase_client as sc

    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "1"}])
    with patch.object(sc, "_get_service_client", return_value=mock_client) as mock_svc:
        res = sc.save_scan({"file_name": "a.exe", "sha256": "uniq-svc-test",
                            "user_id": "u1", "result": "benign"}, user_jwt="jwt-token-123")
        assert res.get("saved") is True
        mock_svc.assert_called_once_with()
        sent = mock_client.table.return_value.insert.call_args[0][0]
        assert sent["user_id"] == "u1"  # user_id del JWT, no del cliente

    # PostgREST auth propagation se mantiene para modo Opcion A pura (fallback sin service key)
    with patch.dict("os.environ", {"SUPABASE_ANON_KEY": "test-anon-key"}):
        with patch("supabase.create_client") as mock_create:
            fake = MagicMock()
            mock_create.return_value = fake
            sc._get_supabase_client(user_jwt="jwt-token-123")
            fake.postgrest.auth.assert_called_once_with("jwt-token-123")


def test_save_scan_fallback_anon_jwt_without_service_key():
    """Sin service key, fallback a anon+JWT (Opcion A pura)."""
    from backend.app.integrations import supabase_client as sc

    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "1"}])
    with patch.object(sc, "_get_service_client", side_effect=RuntimeError("no key")):
        with patch.object(sc, "_get_supabase_client", return_value=mock_client) as mock_get:
            res = sc.save_scan({"file_name": "a.exe", "sha256": "uniq-fallback-test",
                                "user_id": "u1", "result": "benign"}, user_jwt="jwt-token-123")
            assert res.get("saved") is True
            mock_get.assert_called_once_with(user_jwt="jwt-token-123")


def test_save_scan_without_user_id_is_permanent():
    """Fail-secure: sin user_id del JWT no se persiste ni se encola."""
    from backend.app.integrations import supabase_client as sc

    with patch.object(sc, "_fallback_offline") as mock_q:
        res = sc.save_scan({"file_name": "anon.exe", "result": "benign"})
        assert res.get("saved") is False
        assert res.get("permanent") is True
        assert res.get("category") == "auth"
        mock_q.assert_not_called()


def test_rls_failure_is_permanent_no_queue():
    from backend.app.integrations import supabase_client as sc

    assert sc._classify_supabase_error(Exception("42501 violates row-level security")) == "rls"
    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.side_effect = Exception(
        "42501 violates row-level security policy")
    with patch.object(sc, "_get_supabase_client", return_value=mock_client):
        with patch.object(sc, "_fallback_offline") as mock_q:
            res = sc.save_scan({"file_name": "a.exe", "user_id": "u1"})
            assert res.get("permanent") is True
            assert res.get("category") == "rls"
            mock_q.assert_not_called()


def test_transient_goes_to_offline_queue():
    from backend.app.integrations import supabase_client as sc

    assert sc._classify_supabase_error(Exception("connection timeout")) == "transient"
    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.side_effect = Exception("connection timed out")
    with patch.object(sc, "_get_supabase_client", return_value=mock_client):
        with patch.object(sc, "_fallback_offline") as mock_q:
            res = sc.save_scan({"file_name": "a.exe", "user_id": "u1"})
            assert res.get("saved") is False
            assert res.get("permanent") is not True
            mock_q.assert_called_once()


def test_unique_violation_deduplicates():
    from backend.app.integrations import supabase_client as sc

    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.side_effect = Exception(
        '23505 duplicate key value violates unique constraint "uq_scan_results_sha_user"')
    with patch.object(sc, "_get_supabase_client", return_value=mock_client):
        res = sc.save_scan({"file_name": "a.exe", "sha256": "dup", "user_id": "u1"})
        assert res.get("deduplicated") is True
        assert res.get("category") == "unique_violation"


def test_confidence_prefers_final_verdict_level():
    """confidence (TEXT) usa el nivel F2 ('High') antes que el float legacy del DTO."""
    from backend.app.integrations import supabase_client as sc

    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "1"}])
    data = _suspicious_scan()
    data["sha256"] = "f42-confidence-mapping"
    data["confidence"] = 0.0  # DTO legacy float (score ML)
    data["final_verdict"] = {"verdict": "suspicious", "confidence": "High", "score": 0.29}
    with patch.object(sc, "_get_service_client", return_value=mock_client):
        res = sc.save_scan(data, user_jwt="t")
        assert res.get("saved") is True
        sent = mock_client.table.return_value.insert.call_args[0][0]
        assert sent["confidence"] == "High"  # nivel F2, no "0.0"
        assert sent["score"] == 0.0  # score = probabilidad ML (documentado)


def test_f4_fields_in_record_and_json_safe():
    from backend.app.integrations import supabase_client as sc
    from pathlib import Path
    from datetime import datetime, timezone
    import numpy as np

    data = _suspicious_scan()
    data["when"] = datetime(2026, 1, 1, tzinfo=timezone.utc)
    data["path"] = Path("/tmp/a.exe")
    data["n"] = np.float64(0.5)
    safe = sc._safe_json(data)
    assert safe["when"] == "2026-01-01T00:00:00+00:00"
    assert safe["path"] == "/tmp/a.exe"
    assert safe["n"] == 0.5

    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "1"}])
    with patch.object(sc, "_get_supabase_client", return_value=mock_client):
        res = sc.save_scan(data, user_jwt="t")
        assert res.get("saved") is True
        sent = mock_client.table.return_value.insert.call_args[0][0]
        assert isinstance(sent["evidences"], list) and len(sent["evidences"]) == 2
        assert sent["final_verdict"]["verdict"] == "suspicious"
        assert sent["correlation"]["score"] == 0.29


# ---------------------------------------------------------------------------
# LLM — Caso A: detector SUSPICIOUS llega al prompt como SUSPICIOUS
# ---------------------------------------------------------------------------

def test_llm_case_a_suspicious_reaches_prompt():
    summary = extract_scan_summary(_suspicious_scan())
    assert summary["detector"]["verdict"] == "suspicious"
    prompt = build_llm_prompt(_suspicious_scan())
    assert '"verdict": "suspicious"' in prompt
    assert "Unknown" not in prompt.split("SCAN_SUMMARY:")[1].split('"legacy"')[0].replace(
        '"verdict": "unknown"', "")


def test_llm_case_a_no_fake_score():
    summary = extract_scan_summary(_suspicious_scan())
    assert summary["detector"]["correlation_score"] == 0.29
    # El default enganoso score=-1.0 ya no existe en el bloque detector
    assert "score" not in summary["detector"] or summary["detector"].get("score") is None


# ---------------------------------------------------------------------------
# LLM — Caso B: detector MALICIOUS, LLM no puede producir BENIGN
# ---------------------------------------------------------------------------

def test_llm_case_b_malicious_rejects_benign_threat():
    scan = _suspicious_scan()
    scan["result"] = "malicious"
    scan["final_verdict"] = {"verdict": "malicious", "risk_level": "critical"}
    v = _validate_llm_response({"threat_level": "low", "analysis": "todo bien"}, scan)
    assert v["llm_inconsistent"] is True
    fixed = _normalize_llm_response(
        {"threat_level": "low", "analysis": "todo bien"}, scan, v)
    assert fixed["threat_level"] == "high"
    assert fixed["llm_corrected"] is True
    # El detector no se toca
    assert scan["result"] == "malicious"


# ---------------------------------------------------------------------------
# LLM — Caso C: detector BENIGN explica benignidad sin inventar amenazas
# ---------------------------------------------------------------------------

def test_llm_case_c_benign_accepts_low_and_rejects_critical():
    scan = {"result": "benign", "risk_level": "low", "operational_status": "CLEAN",
            "final_verdict": {"verdict": "benign"}}
    v_ok = _validate_llm_response({"threat_level": "low", "analysis": "sin hallazgos"}, scan)
    assert v_ok["llm_inconsistent"] is False
    v_bad = _validate_llm_response({"threat_level": "critical", "analysis": "ransomware"}, scan)
    assert v_bad["llm_inconsistent"] is True


# ---------------------------------------------------------------------------
# LLM — Caso D: contradiccion ML benign + PE/overlay suspicious se refleja
# ---------------------------------------------------------------------------

def test_llm_case_d_contradiction_in_summary_and_template():
    scan = _suspicious_scan()
    summary = extract_scan_summary(scan)
    assert "contradicted" in (summary["detector"]["contradiction"] or "")
    tpl = TemplateExplainer()
    parsed = tpl.explain_from_scan_result(scan)
    assert parsed["threat_level"] in ("medium", "high", "critical")
    assert "overlay_ratio" in parsed["analysis"] or "Contradicción" in parsed["analysis"]


# ---------------------------------------------------------------------------
# LLM — Caso E: family likelihoods sin evidencia -> no concluyente
# ---------------------------------------------------------------------------

def test_llm_case_e_family_inconclusive_in_template():
    scan = _suspicious_scan()  # top_family None, likelihoods dispersos bajos
    tpl = TemplateExplainer()
    parsed = tpl.explain_from_scan_result(scan)
    assert "Familia no determinada / no concluyente" in parsed["analysis"]
    prompt = build_llm_prompt(scan)
    assert "Familia no determinada / no concluyente" in prompt


# ---------------------------------------------------------------------------
# LLM — Caso F: provider caido, detector intacto
# ---------------------------------------------------------------------------

def test_llm_case_f_provider_failure_keeps_detector():
    class _Broken:
        def generate(self, prompt: str, *, model=None) -> str:
            raise RuntimeError("boom: 503 Service Unavailable")

    svc = ExplanationService(clients={"groq": _Broken(), "gemini": _Broken()})
    scan = _suspicious_scan()
    out = svc.explain(scan)
    assert out["_metadata"]["provider_used"] == "template"
    assert scan["result"] == "suspicious"  # detector intacto
    assert scan["final_verdict"]["verdict"] == "suspicious"
    parsed = out["parsed_response"]
    assert parsed["threat_level"] in ("medium", "high", "critical")


# ---------------------------------------------------------------------------
# LLM — Caso G: respuesta contradictoria se normaliza, no se presenta como valida
# ---------------------------------------------------------------------------

def test_llm_case_g_contradictory_response_normalized():
    class _Liar:
        def generate(self, prompt: str, *, model=None) -> str:
            import json as _j
            return _j.dumps({
                "analysis": "archivo benigno sin hallazgos",
                "threat_level": "low",
                "behavior_summary": "software legitimo",
                "recommended_actions": ["nada"],
            })

    svc = ExplanationService(clients={"groq": _Liar()})
    scan = _suspicious_scan()
    out = svc.explain(scan)
    assert out["_metadata"]["provider_used"] == "groq"
    parsed = out["parsed_response"]
    assert parsed["llm_inconsistent"] is True
    assert parsed["threat_level"] in ("medium", "high", "critical")
    assert parsed.get("llm_corrected") is True
    assert "Corrección automática" in parsed["analysis"]
