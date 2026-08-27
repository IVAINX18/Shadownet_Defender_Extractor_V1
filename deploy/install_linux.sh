#!/usr/bin/env bash
# =============================================================================
# deploy/install_linux.sh — Instalador de ShadowNet Defender para Linux
#
# Tarea 20.2: Python >= 3.10, no-root check, usuario shadownet,
#             pip install, systemctl enable+start
#
# Uso:
#   sudo bash deploy/install_linux.sh [--source-dir <ruta>]
#
# Requisitos previos:
#   - Python 3.10+ instalado
#   - systemd disponible
#   - Ejecutar con sudo (no como root directo)
# =============================================================================

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Configuración ─────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/shadownet"
SERVICE_USER="shadownet"
SERVICE_FILE="/etc/systemd/system/shadownet.service"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIN_PYTHON_MINOR=10  # Python 3.10+

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-dir) SOURCE_DIR="$2"; shift 2 ;;
        -h|--help)
            echo "Uso: sudo bash $0 [--source-dir <ruta>]"
            exit 0 ;;
        *) error "Argumento desconocido: $1" ;;
    esac
done

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║        ShadowNet Defender — Instalador Linux         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── 1. Verificar que NO se ejecuta como root directo ─────────────────────────
info "Verificando privilegios..."
if [[ "${EUID}" -eq 0 ]] && [[ -z "${SUDO_USER:-}" ]]; then
    error "No ejecutar como root directo. Usa: sudo bash $0"
fi
ok "Ejecutado con sudo por usuario: ${SUDO_USER:-$(whoami)}"

# ── 2. Verificar Python >= 3.10 ───────────────────────────────────────────────
info "Verificando Python >= 3.10..."
PYTHON_BIN=""
for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo "0")
        major=$("$candidate" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo "0")
        if [[ "$major" -eq 3 ]] && [[ "$ver" -ge $MIN_PYTHON_MINOR ]]; then
            PYTHON_BIN="$candidate"
            full_ver=$("$candidate" --version 2>&1)
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    error "Python 3.${MIN_PYTHON_MINOR}+ no encontrado. Instálalo con: apt install python3.11"
fi
ok "Python encontrado: $full_ver ($PYTHON_BIN)"

# ── 3. Crear usuario shadownet (sin shell, sin directorio home) ───────────────
info "Configurando usuario de servicio '${SERVICE_USER}'..."
if ! id "${SERVICE_USER}" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    ok "Usuario '${SERVICE_USER}' creado."
else
    ok "Usuario '${SERVICE_USER}' ya existe."
fi

# ── 4. Crear directorios de instalación ──────────────────────────────────────
info "Creando estructura en ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"/{models,quarantine,data/test_set,logs,rules}

# Copiar código fuente
if [[ -d "$SOURCE_DIR" ]]; then
    rsync -a --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' \
          --exclude='.git' --exclude='tests' \
          "${SOURCE_DIR}/" "${INSTALL_DIR}/"
    ok "Código copiado desde ${SOURCE_DIR}"
else
    error "Directorio fuente no encontrado: ${SOURCE_DIR}"
fi

# ── 5. Crear virtualenv e instalar dependencias ───────────────────────────────
info "Creando entorno virtual en ${INSTALL_DIR}/.venv..."
"$PYTHON_BIN" -m venv "${INSTALL_DIR}/.venv"

info "Instalando dependencias..."
"${INSTALL_DIR}/.venv/bin/python" -m pip install --upgrade pip --quiet

if [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
    "${INSTALL_DIR}/.venv/bin/python" -m pip install -r "${INSTALL_DIR}/requirements.txt" --quiet
    ok "Dependencias instaladas desde requirements.txt"
else
    warn "requirements.txt no encontrado — instalando deps mínimas..."
    "${INSTALL_DIR}/.venv/bin/python" -m pip install \
        fastapi uvicorn[standard] psutil onnxruntime \
        pydantic python-multipart supabase --quiet
fi

# ── 6. Crear .env si no existe ────────────────────────────────────────────────
if [[ ! -f "${INSTALL_DIR}/.env" ]]; then
    info "Creando .env de ejemplo en ${INSTALL_DIR}/.env..."
    cat > "${INSTALL_DIR}/.env" <<'ENVEOF'
# ShadowNet Defender — Variables de entorno
# ¡EDITAR ANTES DE INICIAR EL SERVICIO!

SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key
SUPABASE_JWT_SECRET=your-jwt-secret
SUPABASE_INCIDENTS_TABLE=incidents

N8N_ENABLED=false
N8N_WEBHOOK_PROD=https://your-n8n-instance/webhook/shadownet-malware

ENVIRONMENT=prod
QUARANTINE_DIR=/opt/shadownet/quarantine
ANALYSIS_TIMEOUT_SECONDS=60
MAX_UPLOAD_MB=50
RATE_LIMIT_SCANS_PER_MINUTE=20
ENVEOF
    chmod 600 "${INSTALL_DIR}/.env"
    warn "⚠  Edita ${INSTALL_DIR}/.env con tus credenciales reales antes de iniciar el servicio."
fi

# ── 7. Ajustar permisos ───────────────────────────────────────────────────────
info "Ajustando permisos..."
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
chmod 700 "${INSTALL_DIR}/quarantine"
chmod 750 "${INSTALL_DIR}"
ok "Permisos configurados."

# ── 8. Instalar systemd service ───────────────────────────────────────────────
info "Instalando servicio systemd..."
cp "${SOURCE_DIR}/deploy/shadownet.service" "${SERVICE_FILE}"
# Actualizar rutas absolutas en el service file
sed -i "s|/opt/shadownet|${INSTALL_DIR}|g" "${SERVICE_FILE}"

systemctl daemon-reload
systemctl enable shadownet.service
ok "Servicio instalado y habilitado para arranque automático."

# ── 9. Verificar modelo ONNX ─────────────────────────────────────────────────
if [[ ! -f "${INSTALL_DIR}/models/best_model.onnx" ]]; then
    warn "⚠  Modelo ONNX no encontrado en ${INSTALL_DIR}/models/best_model.onnx"
    warn "   Cópialo antes de iniciar el servicio."
else
    ok "Modelo ONNX verificado."
fi

# ── 10. Iniciar servicio ──────────────────────────────────────────────────────
if [[ -f "${INSTALL_DIR}/models/best_model.onnx" ]] && \
   [[ -f "${INSTALL_DIR}/models/scaler.pkl" ]]; then
    info "Iniciando servicio shadownet..."
    systemctl start shadownet.service
    sleep 2
    if systemctl is-active --quiet shadownet.service; then
        ok "Servicio iniciado correctamente."
        systemctl status shadownet.service --no-pager | head -15
    else
        warn "El servicio no arrancó. Revisa los logs: journalctl -u shadownet -n 50"
    fi
else
    warn "Modelos no encontrados — servicio NO iniciado."
    warn "Una vez copiados los modelos, ejecuta: systemctl start shadownet"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Instalación completada. Próximos pasos:             ║"
echo "║  1. Edita /opt/shadownet/.env con tus credenciales   ║"
echo "║  2. Copia los modelos a /opt/shadownet/models/       ║"
echo "║  3. sudo systemctl start shadownet                   ║"
echo "║  4. Verifica: curl http://127.0.0.1:8000/health      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
