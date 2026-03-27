# Frontend — React + Electron Build Walkthrough

## What Was Built

Full desktop frontend for ShadowNet Defender: **React (Vite) + TailwindCSS + Electron**.

### File Structure

```
frontend/
├── .env                          # VITE_SUPABASE_URL, VITE_SUPABASE_ANON_KEY, VITE_API_URL
├── index.html                    # Custom title + Inter font
├── package.json                  # Electron scripts + builder config
├── vite.config.js                # TailwindCSS plugin + API proxy
├── electron/
│   ├── main.js                   # BrowserWindow, contextIsolation, dev/prod loading
│   └── preload.js                # Secure contextBridge
└── src/
    ├── index.css                 # Dark cybersecurity design system
    ├── main.jsx                  # React entry
    ├── App.jsx                   # Router + Auth + Token sync
    ├── context/AuthContext.jsx   # Supabase Auth (login/register/logout/session)
    ├── services/api.js           # Axios + JWT interceptor (scanFile, explainResult, etc.)
    ├── components/
    │   ├── Layout.jsx            # Sidebar + Outlet shell
    │   ├── Sidebar.jsx           # Nav links + user info + logout
    │   ├── FileUpload.jsx        # Drag & drop + click-to-browse
    │   ├── ScanResultCard.jsx    # Color-coded result + metrics + LLM explain
    │   ├── StatusBadge.jsx       # benign/suspicious/malicious badges
    │   └── LoadingSpinner.jsx    # Animated spinner
    └── pages/
        ├── LoginPage.jsx         # Email/password login
        ├── RegisterPage.jsx      # Registration with validation
        ├── DashboardPage.jsx     # System health + quick scan CTA
        ├── ScanPage.jsx          # File upload → scan → result → explain
        └── HistoryPage.jsx       # Real-time process monitor + history tabs
```

---

## Build Verification

| Check | Result |
|-------|--------|
| `npm install` | ✅ 524 packages, 0 vulnerabilities |
| `npm run build` | ✅ 125 modules, 725ms, 0 errors |
| Dev server `:5173` | ✅ Serving correctly |
| HTML title | ✅ "ShadowNet Defender" |
| Inter font | ✅ Preloaded from Google Fonts |

### Production Bundle
```
dist/index.html                   0.83 kB
dist/assets/index-CEUnGpKE.css   18.13 kB
dist/assets/index-J9UBcnsC.js   457.36 kB (135.92 kB gzip)
```

---

## How to Run

```bash
# Dev mode (React only)
cd frontend && npm run dev

# Dev mode (React + Electron window)
cd frontend && npm run electron:dev

# Production build
cd frontend && npm run build

# Package for Linux (.deb)
cd frontend && npm run dist:linux

# Package for Windows (.exe)
cd frontend && npm run dist:win
```

---

## Key Design Decisions

1. **TailwindCSS v4** — using `@tailwindcss/vite` plugin with `@theme` directive for custom tokens
2. **Supabase SDK** in frontend — direct auth calls, token managed in Context
3. **Token sync** — [TokenSync](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/frontend/src/App.jsx#39-52) component bridges `AuthContext.token` → [api.js](file:///home/ivainx18/Documentos/Shadownet_Defender_Extractor_V2/frontend/src/services/api.js) interceptor
4. **Electron security** — `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`
5. **Dark theme** — glassmorphism cards, gradient accents, micro-animations
