# ShadowNet Defender — Frontend Build Walkthrough

## Summary

Full React + Electron desktop app built and refined to production quality.

---

## Backend Enhancements

| Feature | Detail |
|---------|--------|
| `config.py` | `MAX_UPLOAD_MB` from env (default 200, min 100) |
| `GET /health` | Includes `max_upload_mb` for frontend alignment |
| `GET /scan/recent` | Live data from Supabase via [fetch_recent_scans](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/backend/app/integrations/supabase_client.py#160-206) |
| [realtime_service.py](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/backend/app/services/realtime_service.py) | Double-pass CPU sampling so `cpu_percent > 0` |

## Electron (preload.js)

- [getSystemMetrics()](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/frontend/electron/preload.js#115-116): CPU (two-sample), RAM (`os.totalmem/freemem`), disk (`fs.promises.statfs`)
- `contextIsolation: true`, `nodeIntegration: false`

## Frontend Features

| File | Purpose |
|------|---------|
| `useDashboardBackend.js` | Polling: health ~8s, realtime ~4s, recent ~15s |
| `useElectronSystemMetrics.js` | System metrics via Electron bridge, fallback in browser |
| `utils/dashboardStats.js` | Aggregated stats from `/scan/recent` |
| [DashboardPage.jsx](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/frontend/src/pages/DashboardPage.jsx) | Live data — no mocks — backend status, processes, CPU/RAM/disk |
| [FileUpload.jsx](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/frontend/src/components/FileUpload.jsx) + [ScanPage.jsx](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/frontend/src/pages/ScanPage.jsx) | Upload limit aligned with `/health`, 50MB warning, 300s timeout |
| [HistoryPage.jsx](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/frontend/src/pages/HistoryPage.jsx) | CPU%, Mem%, RSS MB columns, risk badges |
| [api.js](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/frontend/src/services/api.js) | [getRecentScans](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/frontend/src/services/api.js#117-125), increased scan timeout |
| `constants/uploadLimits.js` | Hard limit from backend config |

## Key Fixes

1. **TailwindCSS removed** — `@import "tailwindcss"` + `@tailwindcss/vite` plugin caused blank page
2. **[.env](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/.env) format** — `//` comments → `#` (`.env` doesn't support JS comments)
3. **`@vitejs/plugin-react`** → **`@vitejs/plugin-react-swc`** (fixed `$RefreshSig$` error with Vite 8 + Node 20)
4. **Routing** — page required `/login` in URL; `BrowserRouter` needs explicit route or fallback
5. **`AuthContext.jsx`** — null checks prevent crash if Supabase env vars missing

## Config

```bash
# Backend .env
MAX_UPLOAD_MB=200  # integer ≥ 100

# Frontend .env (optional, /health overrides)
VITE_MAX_UPLOAD_MB=200
```

## Scripts

```bash
cd frontend
npm run dev          # Vite dev server
npm run electron:dev # React + Electron
npm run dist:linux   # .deb + .AppImage
npm run dist:win     # .exe (NSIS)
```
