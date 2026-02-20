# ☁️ Cloudflare Tunnel — Exponer Ollama públicamente

## ¿Por qué necesitamos esto?

ShadowNet Defender tiene su **backend FastAPI desplegado en Render** (nube), pero **Ollama corre localmente** en la máquina del desarrollador. Para que Render pueda consumir Ollama, necesitamos darle una **URL pública HTTPS**.

**Cloudflare Tunnel** crea un túnel seguro desde tu máquina local hacia Internet, sin necesidad de abrir puertos en tu router ni configurar DNS manualmente.

```
┌──────────────────┐     HTTPS      ┌─────────────────────┐     HTTP       ┌──────────────┐
│  Render (FastAPI) │ ──────────────▶│  Cloudflare Tunnel  │──────────────▶│ Ollama :11434│
│  (nube)           │                │  *.trycloudflare.com│               │ (tu PC local)│
└──────────────────┘                └─────────────────────┘               └──────────────┘
```

---

## 1. Instalar `cloudflared`

### Linux (Debian/Ubuntu)

```bash
# Método 1: Paquete oficial
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb

# Método 2: Binario directo
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
chmod +x cloudflared
sudo mv cloudflared /usr/local/bin/
```

### macOS

```bash
brew install cloudflare/cloudflare/cloudflared
```

### Windows

```powershell
winget install --id Cloudflare.cloudflared
```

### Verificar instalación

```bash
cloudflared --version
# Ejemplo de salida: cloudflared version 2024.x.x
```

---

## 2. (Primera vez) Login en Cloudflare

> **Nota:** Para **quick tunnels** (túneles rápidos temporales) **NO necesitas login**.
> Solo necesitas login si quieres crear un **named tunnel** con dominio estable.

```bash
# Solo si quieres named tunnel (opcional):
cloudflared tunnel login
# Se abrirá el navegador para autenticarte con tu cuenta de Cloudflare
```

---

## 3. Iniciar Quick Tunnel (URL temporal)

### Prerrequisito: Ollama debe estar corriendo

```bash
# Verificar que Ollama está activo:
curl http://localhost:11434/v1/models
```

### Comando para exponer Ollama

```bash
cloudflared tunnel --url http://localhost:11434 --http-host-header="localhost:11434"
```

> ⚠️ **IMPORTANTE:** El flag `--http-host-header="localhost:11434"` es **obligatorio**.
> Sin él, Ollama rechaza las peticiones porque el header `Host` no coincide con lo que espera.

### Salida esperada

```
2024-XX-XX INF +----------------------------+
2024-XX-XX INF |  Your quick Tunnel has been created! Visit it at:
2024-XX-XX INF |  https://random-string.trycloudflare.com
2024-XX-XX INF +----------------------------+
```

**Copia esa URL.** Es tu endpoint público de Ollama.

### URL OpenAI-compatible

La URL completa para usar como `base_url` en el cliente OpenAI es:

```
https://random-string.trycloudflare.com/v1
```

---

## 4. Verificar que funciona

Desde **otra máquina** o desde el navegador:

```bash
# Listar modelos disponibles
curl https://random-string.trycloudflare.com/v1/models

# Test de generación (chat completions, formato OpenAI)
curl https://random-string.trycloudflare.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3.2:3b",
    "messages": [{"role": "user", "content": "Hello!"}],
    "temperature": 0.7
  }'
```

---

## 5. Configurar en Render

Ve al **Dashboard de Render** → tu servicio `shadownet-defender-api` → **Environment**:

| Variable          | Valor                                        |
| ----------------- | -------------------------------------------- |
| `OLLAMA_BASE_URL` | `https://random-string.trycloudflare.com/v1` |
| `OLLAMA_MODEL`    | `llama3.2:3b`                                |

> Después de cambiar las variables, Render redesplegará automáticamente.

---

## 6. ⚠️ Limitaciones del Quick Tunnel

| Aspecto            | Quick Tunnel                  | Named Tunnel                   |
| ------------------ | ----------------------------- | ------------------------------ |
| **URL**            | Cambia cada vez que reinicias | Fija (tu dominio)              |
| **Requiere login** | No                            | Sí                             |
| **Ideal para**     | Desarrollo, demos rápidas     | Producción, demos estables     |
| **Costo**          | Gratis                        | Gratis (con cuenta Cloudflare) |

### Crear Named Tunnel (URL estable para demos)

```bash
# 1. Login (si no lo has hecho)
cloudflared tunnel login

# 2. Crear tunnel con nombre
cloudflared tunnel create shadownet-ollama

# 3. Configurar DNS (necesitas un dominio en Cloudflare)
cloudflared tunnel route dns shadownet-ollama ollama.tudominio.com

# 4. Crear archivo de configuración
cat > ~/.cloudflared/config.yml << EOF
tunnel: shadownet-ollama
credentials-file: /home/$USER/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: ollama.tudominio.com
    service: http://localhost:11434
    originRequest:
      httpHostHeader: "localhost:11434"
  - service: http_status:404
EOF

# 5. Ejecutar
cloudflared tunnel run shadownet-ollama
```

---

## 7. Script rápido para desarrollo diario

Crea un alias o script para tu flujo diario:

```bash
#!/bin/bash
# start-tunnel.sh — Inicia Ollama + Cloudflare Tunnel
echo "🚀 Iniciando Ollama..."
ollama serve &
sleep 3

echo "☁️  Iniciando Cloudflare Tunnel..."
echo "📋 Copia la URL https://*.trycloudflare.com que aparezca abajo"
echo "📋 Pégala en Render → Environment → OLLAMA_BASE_URL (agrega /v1 al final)"
echo ""
cloudflared tunnel --url http://localhost:11434 --http-host-header="localhost:11434"
```

---

## 8. Auto-sync Quick Tunnel -> Render (sin cambiar variables a mano)

Quick tunnel no da URL estable, pero puedes automatizar la actualización de
`OLLAMA_BASE_URL` en Render cada vez que cambie.

Se agregó el script:

`scripts/render_quick_tunnel_sync.sh`

Qué hace:

1. Inicia `cloudflared` quick tunnel.
2. Detecta la URL `https://*.trycloudflare.com`.
3. Actualiza `OLLAMA_BASE_URL=<url>/v1` en Render por API.
4. (Opcional) dispara deploy en Render.
5. Escribe localmente `.env.tunnel-runtime` con la URL vigente.

### Configuración inicial

```bash
cp .env.render-sync.example .env.render-sync
cp .env.render-values.example .env.render-values
```

Edita `.env.render-sync`:

- `RENDER_API_KEY`
- `RENDER_SERVICE_ID`

Edita `.env.render-values` con las variables estáticas que también quieres
sincronizar a Render (`N8N_*`, `OLLAMA_MODEL`, etc.).

### Ejecutar

```bash
chmod +x scripts/render_quick_tunnel_sync.sh
./scripts/render_quick_tunnel_sync.sh
```

Notas:

- Render no puede "leer automáticamente" un `.env` local de tu PC.
- Este script es el puente: lee archivos `.env` locales y hace sync a Render por API.

---

## Troubleshooting

### Error: "Ollama returns empty response" o "connection refused"

- Verifica que Ollama esté corriendo: `curl http://localhost:11434/v1/models`
- Verifica que el modelo esté descargado: `ollama list`

### Error: "Bad Request" o "invalid host header"

- Asegúrate de incluir `--http-host-header="localhost:11434"` en el comando de cloudflared.

### La URL del tunnel cambió

- Es normal con quick tunnels. Actualiza `OLLAMA_BASE_URL` en Render.
- Para URL estable, usa un **named tunnel** (sección 6).

### Timeout en Render

- Ollama puede tardar 30-120 segundos en responder (especialmente la primera vez que carga un modelo).
- El cliente en `ollama_client.py` tiene `timeout=120` configurado.
- Si persiste, prueba con un modelo más ligero: `phi3:mini` o `llama3.2:1b`.
