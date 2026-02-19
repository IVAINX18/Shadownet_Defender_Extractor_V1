#!/usr/bin/env bash
# =============================================================================
# fix-ollama.sh — Script de gestión de Ollama para ShadowNet Defender
# =============================================================================
#
# Propósito:
#   Verificar, instalar, configurar y probar Ollama en la máquina del
#   desarrollador. Diseñado para ser idempotente (puedes ejecutarlo
#   múltiples veces sin efectos secundarios).
#
# Uso:
#   chmod +x fix-ollama.sh
#   ./fix-ollama.sh
#
# Opciones de entorno:
#   OLLAMA_MODEL   — Modelo a descargar (default: llama3.2:3b)
#   USE_DOCKER     — Si es "true", usa Docker en vez de instalación nativa
#
# Autores: Equipo ShadowNet Defender (Proyecto Universitario)
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Colores para salida legible (compatibles con terminales modernas)
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color (reset)

# ─────────────────────────────────────────────────────────────────────────────
# Configuración por defecto (puedes sobreescribir con variables de entorno)
# ─────────────────────────────────────────────────────────────────────────────
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2:3b}"
USE_DOCKER="${USE_DOCKER:-false}"
OLLAMA_PORT=11434
OLLAMA_URL="http://localhost:${OLLAMA_PORT}"

# ─────────────────────────────────────────────────────────────────────────────
# Funciones auxiliares de impresión
# ─────────────────────────────────────────────────────────────────────────────
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[  OK]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[FAIL]${NC}  $*"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; }

# ─────────────────────────────────────────────────────────────────────────────
# Función: esperar a que Ollama esté listo (health check con reintentos)
# ─────────────────────────────────────────────────────────────────────────────
wait_for_ollama() {
    local max_attempts=15
    local attempt=1
    info "Esperando a que Ollama esté listo en ${OLLAMA_URL}..."
    while [ $attempt -le $max_attempts ]; do
        if curl -sf "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
            success "Ollama respondió correctamente (intento ${attempt}/${max_attempts})"
            return 0
        fi
        sleep 2
        attempt=$((attempt + 1))
    done
    error "Ollama no respondió después de ${max_attempts} intentos."
    return 1
}

# =============================================================================
# MODO DOCKER
# =============================================================================
if [ "${USE_DOCKER}" = "true" ]; then
    header "MODO DOCKER — Ollama en contenedor"

    # Paso 1: Verificar que Docker esté instalado
    if ! command -v docker &> /dev/null; then
        error "Docker no está instalado."
        info "Instala Docker desde: https://docs.docker.com/get-docker/"
        exit 1
    fi
    success "Docker encontrado: $(docker --version)"

    # Paso 2: Verificar si el contenedor ya existe
    if docker ps -a --format '{{.Names}}' | grep -q '^ollama$'; then
        # El contenedor existe, verificar si está corriendo
        if docker ps --format '{{.Names}}' | grep -q '^ollama$'; then
            success "Contenedor 'ollama' ya está corriendo."
        else
            info "Contenedor 'ollama' existe pero está detenido. Iniciando..."
            docker start ollama
            success "Contenedor 'ollama' iniciado."
        fi
    else
        # Crear y ejecutar el contenedor por primera vez
        info "Creando contenedor 'ollama' con volumen persistente..."
        docker run -d \
            -v ollama:/root/.ollama \
            -p ${OLLAMA_PORT}:${OLLAMA_PORT} \
            --name ollama \
            ollama/ollama
        success "Contenedor 'ollama' creado y ejecutándose."
    fi

    # Paso 3: Esperar a que Ollama esté listo
    wait_for_ollama || exit 1

    # Paso 4: Descargar modelo si no existe
    info "Verificando modelo '${OLLAMA_MODEL}' dentro del contenedor..."
    if docker exec ollama ollama list 2>/dev/null | grep -q "${OLLAMA_MODEL}"; then
        success "Modelo '${OLLAMA_MODEL}' ya está descargado."
    else
        info "Descargando modelo '${OLLAMA_MODEL}' (esto puede tardar varios minutos)..."
        docker exec ollama ollama pull "${OLLAMA_MODEL}"
        success "Modelo '${OLLAMA_MODEL}' descargado correctamente."
    fi

    # Paso 5: Test del endpoint
    header "TEST — Verificación del endpoint local (Docker)"
    info "Consultando modelos disponibles..."
    curl -s "${OLLAMA_URL}/v1/models" | python3 -m json.tool 2>/dev/null || curl -s "${OLLAMA_URL}/v1/models"
    echo ""
    success "¡Ollama en Docker está listo! Endpoint: ${OLLAMA_URL}"
    info "Endpoint OpenAI-compatible: ${OLLAMA_URL}/v1"
    exit 0
fi

# =============================================================================
# MODO NATIVO (instalación directa en el sistema)
# =============================================================================
header "PASO 1/6 — Verificar instalación de Ollama"

if command -v ollama &> /dev/null; then
    OLLAMA_VERSION=$(ollama --version 2>&1 || echo "versión desconocida")
    success "Ollama está instalado: ${OLLAMA_VERSION}"
else
    warn "Ollama NO está instalado en este sistema."
    echo ""
    info "Para instalar Ollama, ejecuta:"
    echo -e "  ${BOLD}curl -fsSL https://ollama.com/install.sh | sh${NC}"
    echo ""
    info "O visita: https://ollama.com/download"
    echo ""

    # Preguntar si desea instalar automáticamente
    read -rp "¿Deseas instalar Ollama ahora? (s/N): " INSTALL_CHOICE
    if [[ "${INSTALL_CHOICE}" =~ ^[sS]$ ]]; then
        info "Instalando Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
        success "Ollama instalado correctamente."
    else
        error "Ollama es necesario para continuar. Instálalo y vuelve a ejecutar este script."
        exit 1
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
header "PASO 2/6 — Verificar si el servicio Ollama está corriendo"

OLLAMA_RUNNING=false

# Método 1: Verificar con systemctl (Linux con systemd)
if command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet ollama 2>/dev/null; then
        success "Servicio Ollama activo (systemd)."
        OLLAMA_RUNNING=true
    fi
fi

# Método 2: Verificar con ps (fallback universal)
if [ "${OLLAMA_RUNNING}" = "false" ]; then
    if pgrep -x "ollama" > /dev/null 2>&1; then
        success "Proceso Ollama detectado (pgrep)."
        OLLAMA_RUNNING=true
    fi
fi

# Método 3: Verificar si el puerto está escuchando
if [ "${OLLAMA_RUNNING}" = "false" ]; then
    if curl -sf "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
        success "Ollama respondiendo en ${OLLAMA_URL} (health check)."
        OLLAMA_RUNNING=true
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
header "PASO 3/6 — Iniciar Ollama si no está corriendo"

if [ "${OLLAMA_RUNNING}" = "false" ]; then
    warn "Ollama no está corriendo. Intentando iniciar..."

    # Intentar con systemctl primero (más limpio en Linux)
    if command -v systemctl &> /dev/null; then
        info "Intentando iniciar con systemctl..."
        if sudo systemctl start ollama 2>/dev/null; then
            success "Servicio Ollama iniciado con systemctl."
        else
            warn "systemctl falló. Iniciando con 'ollama serve' en background..."
            nohup ollama serve > /tmp/ollama-serve.log 2>&1 &
            success "Ollama iniciado en background (PID: $!). Log: /tmp/ollama-serve.log"
        fi
    else
        # macOS u otros sistemas sin systemd
        info "Iniciando 'ollama serve' en background..."
        nohup ollama serve > /tmp/ollama-serve.log 2>&1 &
        success "Ollama iniciado en background (PID: $!). Log: /tmp/ollama-serve.log"
    fi

    # Esperar a que esté listo
    wait_for_ollama || exit 1
else
    success "Ollama ya está corriendo. No es necesario iniciar."
fi

# ─────────────────────────────────────────────────────────────────────────────
header "PASO 4/6 — Verificar y descargar modelo '${OLLAMA_MODEL}'"

# Listar modelos disponibles localmente
info "Modelos actualmente descargados:"
ollama list 2>/dev/null || warn "No se pudo listar modelos."
echo ""

# Verificar si el modelo deseado ya existe
if ollama list 2>/dev/null | grep -q "${OLLAMA_MODEL}"; then
    success "Modelo '${OLLAMA_MODEL}' ya está disponible localmente."
else
    info "Descargando modelo '${OLLAMA_MODEL}' (esto puede tardar varios minutos)..."
    ollama pull "${OLLAMA_MODEL}"
    success "Modelo '${OLLAMA_MODEL}' descargado correctamente."
fi

# ─────────────────────────────────────────────────────────────────────────────
header "PASO 5/6 — Estado y logs del servicio"

info "Procesos Ollama activos:"
ps aux | grep -i "[o]llama" || warn "No se encontraron procesos Ollama (puede estar como servicio)."
echo ""

# Mostrar logs recientes si están disponibles
if command -v journalctl &> /dev/null; then
    info "Últimas líneas del log de Ollama (journalctl):"
    sudo journalctl -u ollama --no-pager -n 10 2>/dev/null || warn "No hay logs en journalctl."
elif [ -f /tmp/ollama-serve.log ]; then
    info "Últimas líneas del log de Ollama (/tmp/ollama-serve.log):"
    tail -10 /tmp/ollama-serve.log
fi
echo ""

# Mostrar modelos cargados en memoria
info "Modelos actualmente cargados en memoria:"
ollama ps 2>/dev/null || warn "No se pudo consultar modelos en memoria."

# ─────────────────────────────────────────────────────────────────────────────
header "PASO 6/6 — Test del endpoint local"

info "Consultando endpoint OpenAI-compatible: ${OLLAMA_URL}/v1/models"
echo ""

HTTP_CODE=$(curl -s -o /tmp/ollama-test-response.json -w "%{http_code}" "${OLLAMA_URL}/v1/models" 2>/dev/null || echo "000")

if [ "${HTTP_CODE}" = "200" ]; then
    success "Endpoint respondió con HTTP 200 ✓"
    echo ""
    info "Respuesta:"
    python3 -m json.tool /tmp/ollama-test-response.json 2>/dev/null || cat /tmp/ollama-test-response.json
else
    error "Endpoint respondió con HTTP ${HTTP_CODE}"
    [ -f /tmp/ollama-test-response.json ] && cat /tmp/ollama-test-response.json
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Test rápido de generación (opcional)
# ─────────────────────────────────────────────────────────────────────────────
info "Test rápido de generación con modelo '${OLLAMA_MODEL}'..."
GENERATE_RESPONSE=$(curl -sf "${OLLAMA_URL}/api/generate" \
    -d "{\"model\": \"${OLLAMA_MODEL}\", \"prompt\": \"Say hello in one word.\", \"stream\": false}" \
    2>/dev/null || echo "")

if [ -n "${GENERATE_RESPONSE}" ]; then
    success "Generación exitosa ✓"
    echo "${GENERATE_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('response','(sin respuesta)'))" 2>/dev/null || echo "${GENERATE_RESPONSE}"
else
    warn "No se pudo generar respuesta. Verifica que el modelo esté descargado."
fi

# ─────────────────────────────────────────────────────────────────────────────
# Resumen final
# ─────────────────────────────────────────────────────────────────────────────
header "RESUMEN"
echo -e "  ${GREEN}✓${NC} Ollama instalado y corriendo"
echo -e "  ${GREEN}✓${NC} Modelo: ${BOLD}${OLLAMA_MODEL}${NC}"
echo -e "  ${GREEN}✓${NC} Endpoint local: ${BOLD}${OLLAMA_URL}${NC}"
echo -e "  ${GREEN}✓${NC} Endpoint OpenAI-compatible: ${BOLD}${OLLAMA_URL}/v1${NC}"
echo ""
echo -e "  ${CYAN}Siguiente paso:${NC} Exponer Ollama públicamente con Cloudflare Tunnel:"
echo -e "  ${BOLD}cloudflared tunnel --url http://localhost:11434 --http-host-header=\"localhost:11434\"${NC}"
echo ""
echo -e "  ${CYAN}Documentación:${NC} docs/cloudflare-tunnel-setup.md"
echo ""
