"""
tests/test_ollama_client.py — Tests unitarios para el cliente Ollama (OpenAI SDK)

Estos tests verifican que OllamaClient funciona correctamente usando mocks
del SDK de OpenAI. No requieren Ollama corriendo.
"""

from unittest.mock import MagicMock, patch

import pytest

from core.llm.ollama_client import OllamaClient, OllamaClientConfig


# ─────────────────────────────────────────────────────────────────────────────
# Helpers para crear respuestas mock del SDK de OpenAI
# ─────────────────────────────────────────────────────────────────────────────
def _make_mock_response(content: str = "explicacion"):
    """Crea un objeto mock que simula la respuesta de OpenAI SDK."""
    mock_message = MagicMock()
    mock_message.content = content

    mock_choice = MagicMock()
    mock_choice.message = mock_message

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=20, total_tokens=30)

    return mock_response


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────
def test_ollama_client_generate_success():
    """Verifica que generate() retorna el contenido de la respuesta correctamente."""
    config = OllamaClientConfig(
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2:3b",
    )

    with patch("core.llm.ollama_client.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_mock_response("explicacion")
        MockOpenAI.return_value = mock_client

        client = OllamaClient(config)
        result = client.generate("prompt de prueba")

        assert result == "explicacion"
        mock_client.chat.completions.create.assert_called_once()


def test_ollama_client_generate_with_custom_model():
    """Verifica que se puede sobreescribir el modelo en generate()."""
    config = OllamaClientConfig(
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2:3b",
    )

    with patch("core.llm.ollama_client.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_mock_response("ok")
        MockOpenAI.return_value = mock_client

        client = OllamaClient(config)
        client.generate("test", model="phi3:mini")

        call_kwargs = mock_client.chat.completions.create.call_args
        assert call_kwargs.kwargs["model"] == "phi3:mini"


def test_ollama_client_connection_error():
    """Verifica que un error de conexión se convierte en RuntimeError."""
    from openai import APIConnectionError

    config = OllamaClientConfig(
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2:3b",
    )

    with patch("core.llm.ollama_client.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = APIConnectionError(
            request=MagicMock()
        )
        MockOpenAI.return_value = mock_client

        client = OllamaClient(config)
        with pytest.raises(RuntimeError, match="No se pudo conectar a Ollama"):
            client.generate("prompt")


def test_ollama_client_timeout_error():
    """Verifica que un timeout se convierte en RuntimeError descriptivo."""
    from openai import APITimeoutError

    config = OllamaClientConfig(
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2:3b",
        timeout_seconds=30,
    )

    with patch("core.llm.ollama_client.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = APITimeoutError(
            request=MagicMock()
        )
        MockOpenAI.return_value = mock_client

        client = OllamaClient(config)
        with pytest.raises(RuntimeError, match="no respondió en 30 segundos"):
            client.generate("prompt")


def test_ollama_client_empty_response():
    """Verifica que una respuesta vacía (content=None) lanza RuntimeError."""
    config = OllamaClientConfig(
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2:3b",
    )

    with patch("core.llm.ollama_client.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_mock_response(None)
        # Simular content=None
        mock_client.chat.completions.create.return_value.choices[0].message.content = None
        MockOpenAI.return_value = mock_client

        client = OllamaClient(config)
        with pytest.raises(RuntimeError, match="respuesta vacía"):
            client.generate("prompt")


def test_ollama_client_prod_localhost_raises():
    """Verifica que en ENVIRONMENT=prod con localhost se lanza error."""
    import os

    config = OllamaClientConfig(
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2:3b",
    )

    with patch.dict(os.environ, {"ENVIRONMENT": "prod"}):
        with patch("core.llm.ollama_client.OpenAI"):
            with pytest.raises(RuntimeError, match="OLLAMA_BASE_URL apunta a localhost"):
                OllamaClient(config)
