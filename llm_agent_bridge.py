from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib import error, request


def _http_post_json(url: str, payload: Dict[str, Any], timeout: int = 60) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} calling {url}: {detail}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Network error calling {url}: {exc}") from exc


def normalize_provider(provider: Optional[str]) -> str:
    if not provider:
        return "ollama"
    value = provider.strip().lower()
    if value in {"google", "opal", "google_opal", "google-opal"}:
        return "google_opal"
    if value in {"ollama"}:
        return "ollama"
    raise ValueError(f"Unsupported provider '{provider}'. Use 'ollama' or 'google_opal'.")


@dataclass
class LLMBridgeConfig:
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    google_opal_model: str = os.getenv("GOOGLE_OPAL_MODEL", "gemini-1.5-flash")
    google_opal_api_key: Optional[str] = os.getenv("GOOGLE_OPAL_API_KEY")


class LLMAgentBridge:
    """
    LLM integration layer for ShadowNet Defender.
    Supports:
    - Ollama local inference
    - Google Opal/Gemini via Generative Language API
    """

    def __init__(self, config: Optional[LLMBridgeConfig] = None):
        self.config = config or LLMBridgeConfig()

    @staticmethod
    def build_prompt(scan_result: Dict[str, Any]) -> str:
        return (
            "You are a malware triage analyst.\n"
            "Given this scan result JSON, respond ONLY with valid JSON using keys:\n"
            "risk_level, short_explanation, likely_technique, containment_steps, confidence_note.\n"
            "Keep containment_steps as an array of concise actions.\n\n"
            f"SCAN_RESULT:\n{json.dumps(scan_result, ensure_ascii=True)}\n"
        )

    def explain_scan(
        self,
        scan_result: Dict[str, Any],
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        resolved_provider = normalize_provider(provider)
        prompt = self.build_prompt(scan_result)

        if resolved_provider == "ollama":
            resolved_model = model or self.config.ollama_model
            text = self._call_ollama(prompt=prompt, model=resolved_model)
            return {"provider": "ollama", "model": resolved_model, "response_text": text}

        resolved_model = model or self.config.google_opal_model
        text = self._call_google_opal(prompt=prompt, model=resolved_model)
        return {"provider": "google_opal", "model": resolved_model, "response_text": text}

    def _call_ollama(self, *, prompt: str, model: str) -> str:
        url = f"{self.config.ollama_base_url.rstrip('/')}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }
        data = _http_post_json(url, payload)
        if "response" not in data:
            raise RuntimeError(f"Unexpected Ollama response: {data}")
        return str(data["response"]).strip()

    def _call_google_opal(self, *, prompt: str, model: str) -> str:
        api_key = self.config.google_opal_api_key
        if not api_key:
            raise RuntimeError(
                "Missing GOOGLE_OPAL_API_KEY. Export it before using provider='google_opal'."
            )
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={api_key}"
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2},
        }
        data = _http_post_json(url, payload)
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except Exception as exc:
            raise RuntimeError(f"Unexpected Google Opal response: {data}") from exc
