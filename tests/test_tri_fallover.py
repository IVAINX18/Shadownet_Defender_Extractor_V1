"""
tests/test_tri_fallover.py — Cascada Tri-Fallover (groq -> gemini -> template).

Cubre el contrato del plan docs/TriFallover_Groq_Gemini_Template.md:
- Fallover inmediato ante 429/timeout/red sin reintentos.
- Fallover cuando falta la API key de un proveedor (ValueError).
- Template como última instancia: explain() nunca lanza.
- _metadata.provider_used siempre presente para UI/telemetría.
- Compatibilidad: provider explícito y clientes inyectados siguen ganando.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from core.llm.explanation_service import ExplanationService, ExplanationServiceConfig
from core.llm.template_explainer import TemplateExplainer

try:
    from openai import APIConnectionError, APITimeoutError, RateLimitError
except ImportError:  # pragma: no cover
    pytest.skip("openai no instalado", allow_module_level=True)


VALID_LLM_JSON = json.dumps(
    {
        "analysis": "overlay_ratio alto, entropía elevada",
        "threat_level": "high",
        "behavior_summary": "dropper con payload cifrado",
        "recommended_actions": ["aislar host"],
    }
)

SAMPLE_SCAN = {
    "label": "MALWARE",
    "score": 0.92,
    "confidence": "High",
    "details": {"entropy": 7.9, "suspicious_imports": ["VirtualAlloc"]},
}


def _rate_limit_error() -> RateLimitError:
    resp = MagicMock()
    resp.status_code = 429
    resp.headers = {}
    return RateLimitError(message="Too Many Requests", response=resp, body=None)


def _connection_error() -> APIConnectionError:
    return APIConnectionError(message="net down", request=MagicMock())


def _client_returning(payload: str) -> MagicMock:
    client = MagicMock()
    client.generate.return_value = payload
    return client


def _client_raising(exc: Exception) -> MagicMock:
    client = MagicMock()
    client.generate.side_effect = exc
    return client


class TestTriFailoverCascade:
    def test_groq_429_falls_to_gemini(self):
        """Cuota Groq excedida (429) debe conmutar a Gemini sin reintento."""
        groq = _client_raising(_rate_limit_error())
        gemini = _client_returning(VALID_LLM_JSON)
        svc = ExplanationService(
            config=ExplanationServiceConfig(default_provider="groq"),
            clients={"groq": groq, "gemini": gemini, "template": TemplateExplainer()},
        )

        result = svc.explain(SAMPLE_SCAN)

        assert result["_metadata"]["provider_used"] == "gemini"
        assert result["provider"] == "gemini"
        assert groq.generate.call_count == 1  # sin reintentos
        assert result["parsed_response"]["threat_level"] == "high"

    def test_groq_timeout_gemini_connection_error_falls_to_template(self):
        """Ambas nubes caídas → template determinístico, explain() nunca lanza."""
        clients = {
            "groq": _client_raising(APITimeoutError(request=MagicMock())),
            "gemini": _client_raising(_connection_error()),
        }
        svc = ExplanationService(
            config=ExplanationServiceConfig(default_provider="groq"),
            clients=clients,
        )

        result = svc.explain(SAMPLE_SCAN)

        assert result["_metadata"]["provider_used"] == "template"
        assert result["_metadata"]["fallover"] is True
        pr = result["parsed_response"]
        assert pr["mode"] == "template_offline"
        assert pr["threat_level"] in ("high", "critical")
        assert pr["recommended_actions"]

    def test_missing_key_valueerror_falls_over(self):
        """ValueError por API key ausente trata el proveedor como no disponible."""
        clients = {
            "groq": _client_raising(ValueError("GROQ_API_KEY es requerida")),
            "gemini": _client_returning(VALID_LLM_JSON),
        }
        svc = ExplanationService(
            config=ExplanationServiceConfig(default_provider="groq"),
            clients=clients,
        )

        result = svc.explain(SAMPLE_SCAN)

        assert result["_metadata"]["provider_used"] == "gemini"

    def test_gemini_success_has_no_fallover_flag(self):
        """Primer intento exitoso → fallover=False y errors=None."""
        clients = {"gemini": _client_returning(VALID_LLM_JSON)}
        svc = ExplanationService(
            config=ExplanationServiceConfig(default_provider="gemini"),
            clients=clients,
        )

        result = svc.explain(SAMPLE_SCAN)

        assert result["_metadata"]["provider_used"] == "gemini"
        assert result["_metadata"]["fallover"] is False
        assert result["_metadata"]["errors"] is None

    def test_explicit_provider_short_circuits_cascade(self):
        """provider='ollama' explícito se intenta primero aunque el default sea groq."""
        groq = _client_returning(VALID_LLM_JSON)
        ollama = _client_returning(VALID_LLM_JSON)
        svc = ExplanationService(
            config=ExplanationServiceConfig(default_provider="groq"),
            clients={"groq": groq, "ollama": ollama},
        )

        result = svc.explain(SAMPLE_SCAN, provider="ollama")

        assert result["_metadata"]["provider_used"] == "ollama"
        groq.generate.assert_not_called()

    def test_provider_order_from_env_config(self):
        """LLM_PROVIDER_ORDER controla la prelación sin tocar código (OCP)."""
        svc = ExplanationService(
            config=ExplanationServiceConfig(
                default_provider="gemini",
                provider_order=["gemini", "groq", "template"],
            ),
            clients={
                "gemini": _client_raising(_rate_limit_error()),
                "groq": _client_returning(VALID_LLM_JSON),
            },
        )

        result = svc.explain(SAMPLE_SCAN)

        assert result["_metadata"]["provider_used"] == "groq"

    def test_template_always_used_when_nothing_registered(self):
        """Sin clientes inyectados ni factories disponibles → template igual."""
        svc = ExplanationService(
            config=ExplanationServiceConfig(default_provider="groq"),
            clients={"template": TemplateExplainer()},
        )
        # Bloquear la construcción perezosa de clientes reales (sin keys en CI)
        with patch.dict("os.environ", {"GROQ_API_KEY": "", "GEMINI_API_KEY": ""}, clear=False):
            result = svc.explain(SAMPLE_SCAN)
        assert result["_metadata"]["provider_used"] == "template"


class TestTemplateExplainerContract:
    def test_high_risk_scan_produces_quarantine_actions(self):
        tpl = TemplateExplainer()
        parsed = tpl.explain_from_scan_result(
            {
                "file_name": "malware_test.exe",
                "operational_status": "DANGEROUS",
                "risk_level": "HIGH",
                "score": 0.98,
                "overlay_analysis": {"overlay_detected": True, "overlay_ratio": 0.85},
                "yara_matches": [{"rule_name": "Ransomware_LockBit"}],
            }
        )
        assert parsed["threat_level"] in ("high", "critical")
        assert any("cuarentena" in a.lower() for a in parsed["recommended_actions"])
        assert "Ransomware_LockBit" in parsed["analysis"]
        assert parsed["llm_confidence"] == 1.0

    def test_benign_scan_produces_no_action(self):
        tpl = TemplateExplainer()
        parsed = tpl.explain_from_scan_result(
            {"label": "BENIGN", "score": 0.01, "file_name": "notepad.exe", "details": {}}
        )
        assert parsed["threat_level"] == "none"
        assert parsed["recommended_actions"] == ["No se requieren acciones reactivas."]

    def test_generate_interface_compat_extracts_summary_from_prompt(self):
        """generate() (contrato LLMClient) recupera SCAN_SUMMARY del prompt."""
        from core.llm.prompt_builder import build_llm_prompt

        tpl = TemplateExplainer()
        prompt = build_llm_prompt(
            {"label": "MALWARE", "score": 0.93, "confidence": "High",
             "details": {"entropy": 7.9, "suspicious_imports": ["VirtualAlloc"]}}
        )
        out = tpl.generate(prompt)
        parsed = json.loads(out)
        assert parsed["threat_level"] in ("high", "critical")
        assert "VirtualAlloc" in parsed["analysis"]

    def test_malformed_input_never_raises(self):
        """Fail-soft: entradas basura producen dict válido, no excepciones."""
        tpl = TemplateExplainer()
        for junk in ({}, None, {"score": "no-numero"}, {"details": "no-dict"}):
            parsed = tpl.explain_from_scan_result(junk if isinstance(junk, dict) else {})
            assert "threat_level" in parsed
            assert "recommended_actions" in parsed


class TestGeminiClientUnit:
    def test_no_key_raises_value_error(self):
        from core.llm.gemini_client import GeminiClient, GeminiClientConfig

        client = GeminiClient(GeminiClientConfig(api_key=""))
        with pytest.raises(ValueError, match="GEMINI_API_KEY"):
            client.generate("prompt")

    def test_generate_sends_json_object_format(self):
        from core.llm.gemini_client import GeminiClient, GeminiClientConfig

        client = GeminiClient(GeminiClientConfig(api_key="test-key"))
        resp = MagicMock()
        resp.choices = [MagicMock(message=MagicMock(content='{"ok": true}'))]
        with patch.object(client._client.chat.completions, "create", return_value=resp) as create:
            out = client.generate("hola", model="gemini-3.5-flash-lite")
        assert out == '{"ok": true}'
        kwargs = create.call_args.kwargs
        assert kwargs["model"] == "gemini-3.5-flash-lite"
        assert kwargs["response_format"] == {"type": "json_object"}

    def test_503_degrades_to_fallback_model_within_gemini(self):
        """503 en el modelo pedido → reintento contra gemini-3.1-flash-lite sin salir de Gemini."""
        from core.llm.gemini_client import (
            GEMINI_FALLBACK_MODEL,
            GeminiClient,
            GeminiClientConfig,
        )
        from openai import APIStatusError

        client = GeminiClient(GeminiClientConfig(api_key="test-key"))
        ok_resp = MagicMock()
        ok_resp.choices = [MagicMock(message=MagicMock(content='{"threat_level": "low"}'))]

        err_503 = APIStatusError(
            message="high demand",
            response=MagicMock(status_code=503, headers={}),
            body=None,
        )
        calls = []

        def fake_create(**kwargs):
            calls.append(kwargs["model"])
            if kwargs["model"] != GEMINI_FALLBACK_MODEL:
                raise err_503
            return ok_resp

        with patch.object(client._client.chat.completions, "create", side_effect=fake_create):
            out = client.generate("hola", model="gemini-3.5-flash-lite")

        assert calls == ["gemini-3.5-flash-lite", GEMINI_FALLBACK_MODEL]
        assert json.loads(out)["threat_level"] == "low"

    def test_prod_http_base_url_rejected(self):
        """En ENVIRONMENT=prod el base_url debe ser HTTPS (política de transporte)."""
        from core.llm.gemini_client import GeminiClient, GeminiClientConfig

        with patch.dict("os.environ", {"ENVIRONMENT": "prod"}):
            with pytest.raises(RuntimeError, match="HTTPS"):
                GeminiClient(
                    GeminiClientConfig(api_key="k", base_url="http://evil.example/")
                )


class TestGroqClientUnit:
    def test_no_key_raises_value_error(self):
        from core.llm.groq_client import GroqClient, GroqClientConfig

        client = GroqClient(GroqClientConfig(api_key=""))
        with pytest.raises(ValueError, match="GROQ_API_KEY"):
            client.generate("prompt")

    def test_default_model_is_gpt_oss_20b(self):
        from core.llm.groq_client import GroqClientConfig

        with patch.dict("os.environ", {"GROQ_MODEL": ""}, clear=False):
            cfg = GroqClientConfig()
        assert cfg.model == "openai/gpt-oss-20b"
