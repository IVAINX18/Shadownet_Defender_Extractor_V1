from core.llm.explanation_service import ExplanationService, ExplanationServiceConfig


class _FakeJsonClient:
    def generate(self, prompt: str, *, model: str | None = None) -> str:
        return (
            "{"
            "\"resumen_ejecutivo\":\"ok\","
            "\"explicacion_tecnica\":\"detalle\","
            "\"recomendaciones\":[\"aislar host\"]"
            "}"
        )


class _FakeTextClient:
    def generate(self, prompt: str, *, model: str | None = None) -> str:
        return "respuesta libre sin json"


class _FakeFencedJsonClient:
    def generate(self, prompt: str, *, model: str | None = None) -> str:
        return (
            "```json\n"
            "{\n"
            "  \"resumen_ejecutivo\": \"ok fenced\",\n"
            "  \"indicadores_clave\": [\"score\", \"imports\"]\n"
            "}\n"
            "```"
        )


def test_explanation_service_returns_parsed_response_for_json():
    service = ExplanationService(
        config=ExplanationServiceConfig(default_provider="fake", default_model="test-model"),
        clients={"fake": _FakeJsonClient()},
    )

    result = service.explain({"label": "MALWARE", "score": 0.97})

    assert result["provider"] == "fake"
    assert result["model"] == "test-model"
    assert result["response_text"].startswith("{")
    assert result["parsed_response"]["resumen_ejecutivo"] == "ok"


def test_explanation_service_omits_parsed_response_for_plain_text():
    service = ExplanationService(
        config=ExplanationServiceConfig(default_provider="fake", default_model="test-model"),
        clients={"fake": _FakeTextClient()},
    )

    result = service.explain({"label": "MALWARE", "score": 0.97})

    assert result["provider"] == "fake"
    assert result["model"] == "test-model"
    assert result["response_text"] == "respuesta libre sin json"
    assert "parsed_response" not in result


def test_explanation_service_parses_markdown_fenced_json():
    service = ExplanationService(
        config=ExplanationServiceConfig(default_provider="fake", default_model="test-model"),
        clients={"fake": _FakeFencedJsonClient()},
    )

    result = service.explain({"label": "MALWARE", "score": 0.97})

    assert result["provider"] == "fake"
    assert result["model"] == "test-model"
    assert "```json" in result["response_text"]
    assert result["parsed_response"]["resumen_ejecutivo"] == "ok fenced"
