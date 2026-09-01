# Backend Critical Tasks — Walkthrough

## What Was Implemented

All 6 critical priority tasks from the gap analysis, creating 8 new files in the `backend/app/` architecture.

---

## Files Created

| File | Purpose |
|------|---------|
| [dto.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/backend/app/schemas/dto.py) | Pydantic DTOs: `ScanResult`, `ScanResponse`, `ErrorResponse`, `ExplainRequest` + enums |
| [response.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/backend/app/utils/response.py) | `success_response()` / `error_response()` — formato PRD §19.6/19.7 |
| [scan_service.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/backend/app/services/scan_service.py) | `classify_tripartite()`, `scan_single_file()`, `scan_multiple_files()` |
| [supabase_client.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/backend/app/integrations/supabase_client.py) | `save_scan()` / `save_scan_safe()` — persistencia en Supabase |
| [scan.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/backend/app/api/routes/scan.py) | `POST /scan/file`, `POST /scan/multiple` con `UploadFile` |
| [analysis.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/backend/app/api/routes/analysis.py) | `POST /analysis/explain` con `ExplainRequest` DTO |
| [health.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/backend/app/api/routes/health.py) | `GET /health` |
| [main.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/backend/app/main.py) | FastAPI app + CORS + route registration + dotenv |

## Architecture

```
backend/app/
├── main.py                          # App + CORS + routers
├── api/routes/
│   ├── scan.py                      # POST /scan/file, POST /scan/multiple
│   ├── analysis.py                  # POST /analysis/explain
│   └── health.py                    # GET /health
├── schemas/dto.py                   # Pydantic models
├── services/scan_service.py         # ML orchestration + tripartite classification
├── integrations/supabase_client.py  # Supabase persistence
└── utils/response.py               # Standardized responses
```

## Tripartite Classification

| Score | Result | Risk Level |
|-------|--------|------------|
| < 0.4 | `benign` | `low` |
| 0.4 – 0.7 | `suspicious` | `medium` |
| > 0.7 | `malicious` | `high` |

## Verification Results

```
[OK] schemas/dto.py imported
[OK] utils/response.py imported
[OK] classify(0.2)  = benign/low
[OK] classify(0.55) = suspicious/medium
[OK] classify(0.85) = malicious/high
[OK] ScanResult serializes to PRD-compliant JSON
[OK] supabase_client.py imported
[OK] FastAPI app created with all routes and CORS
```

Registered routes:
```
POST /scan/file
POST /scan/multiple
POST /analysis/explain
GET  /health
```

## How to Run

```bash
# From project root:
.venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

# Then open: http://localhost:8000/docs
```

## Environment Variables Required

```env
# .env file
SUPABASE_KEY=<your-supabase-api-key>
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
OLLAMA_BASE_URL=http://127.0.0.1:11434/v1
OLLAMA_MODEL=llama3.2:3b
```

## Dependency Added

`python-multipart` was installed (required by FastAPI for `UploadFile` support).
