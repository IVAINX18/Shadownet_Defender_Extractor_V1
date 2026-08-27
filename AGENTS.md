# AGENTS.md — ShadowNet Defender Extractor V2

## Setup
- Python 3.11 only (`>=3.11,<3.12` — see `.python-version`: 3.11.14). Create venv: `python3.11 -m venv .venv && source .venv/bin/activate`
- Install: `pip install -r requirements.txt` (includes `requirements/base.in` + `ml.in` + `viz.in` + `dev.in`). For prod-only inference: `pip install -r requirements/base.in`.
- No `pyproject.toml` / no build step. No JS build. Env file is ignored by git (`.env`); `backend/app/main.py` auto-loads `.env` via `python-dotenv` if present.

## Run / Dev Servers
- API (FastAPI): `uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload` (reads `HOST`/`PORT` env). Also `uvicorn main:app ...` for legacy root `main.py` (deprecated — use `backend/app/main.py`).
- CLI: `python cli.py scan <file> [--explain --provider ollama --model llama3.2:3b]` and `python cli.py verify-model --manifest model_manifest.json`
- Frontend Electron (if present): roots under `frontend/` + `ui/` — not wired to a single npm script; check `frontend/` dir before running.

## Tests
- All tests: `pytest tests/ -v` (or `.venv/bin/pytest`)
- Single file/case: `pytest tests/test_extractors.py -v` / `pytest tests/test_extractors.py::test_name -v`
- Property tests use Hypothesis — `tests/conftest.py` registers `ci` (100 examples) and `dev` (50) profiles, loads `ci` by default. `hypothesis` is optional.
- Fixtures to reuse: `mock_engine`, `sample_pe_bytes`/`sample_pe_file`, `non_pe_file`, `test_client` (needs `httpx`). Project root is injected into `sys.path` by `conftest.py`/`backend/app/main.py` — don't add duplicate path hacks.
- Scripts verify readiness: `python verify_readiness.py`

## Architecture — Where Code Lives
- `backend/app/` — FastAPI app entry `main.py`; `api/routes/` (scan, analysis, health, quarantine, remediation), `services/`, `api/dependencies/auth.py`, `integrations/supabase_client.py`
- `core/` — scan engine (`engine.py`), LLM layer (`core/llm/`, `llm_agent_bridge.py`), integrations (`core/integrations/n8n_client.py`), automation
- `extractors/` — PE feature extraction → 2381-dim vector (byte hist, entropy, strings/IoCs, headers, sections, import/export hashing)
- `models/` — `best_model.onnx` + `scaler.pkl` + `model_manifest.json` (verified via `/verify-model`)
- `security/`, `utils/`, `configs/`, `frontend/`, `training/`, `evaluation/`, `tools/`, `scripts/` (many scripts live at repo root: `api_server.py`, `cli.py`, `updater.py`)
- `tests/unit/`, `tests/integration/`, `tests/properties/`, `tests/fixtures/`

## Conventions / Gotchas
- 2381 dims is a hard contract — tests assert exact shape, no NaN/Inf, valid histogram/entropy ranges.
- ONNX Runtime is prod inference (no PyTorch in prod). Don't add `torch` to `base.in`.
- LLM is Ollama via OpenAI-compatible API. Env: `OLLAMA_BASE_URL` (`http://127.0.0.1:11434/v1`), `OLLAMA_MODEL`; see `fix-ollama.sh`. Response must be JSON with `analysis`, `threat_level`, `behavior_summary`, `recommended_actions[]`.
- n8n webhooks: `N8N_ENABLED`, `N8N_WEBHOOK_TEST`/`N8N_WEBHOOK_PROD`, `N8N_TIMEOUT_SECONDS=8`, `ENVIRONMENT=dev|prod`, `POST /scan?mode=test|prod`.
- Upload limit: `MAX_UPLOAD_MB` (default 200, floor 100) in `backend/app/config.py`.
- CORS allowed origins from `CORS_ORIGINS` env, default `http://localhost:3000,5173,8080` for Electron.
- Private academic license — not open source. Don't add public license headers.
