#Requires -Version 5.1
<#
.SYNOPSIS
    Instalador de ShadowNet Defender para Windows.

.DESCRIPTION
    Tarea 20.3: Python >= 3.10, pip install, registro de servicio Windows via NSSM.
    Instala ShadowNet Defender como servicio de Windows con arranque automático.

.PARAMETER SourceDir
    Ruta al directorio fuente del proyecto. Por defecto: directorio padre del script.

.PARAMETER InstallDir
    Directorio de instalación. Por defecto: C:\ShadowNet

.PARAMETER Port
    Puerto en el que escucha el backend. Por defecto: 8000

.EXAMPLE
    .\install_windows.ps1
    .\install_windows.ps1 -InstallDir "D:\ShadowNet" -Port 8080

.NOTES
    Requiere ejecución como Administrador.
    NSSM se descarga automáticamente si no está disponible.
#>

[CmdletBinding()]
param(
    [string]$SourceDir   = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$InstallDir  = "C:\ShadowNet",
    [int]$Port           = 8000,
    [string]$ServiceName = "ShadowNetDefender"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helpers ────────────────────────────────────────────────────────────────────
function Write-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      ShadowNet Defender — Instalador Windows         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── 1. Verificar que se ejecuta como Administrador ────────────────────────────
Write-Info "Verificando privilegios de administrador..."
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "Ejecuta este script como Administrador (clic derecho → Ejecutar como administrador)."
}
Write-Ok "Privilegios de administrador confirmados."

# ── 2. Verificar Python >= 3.10 ───────────────────────────────────────────────
Write-Info "Verificando Python >= 3.10..."
$PythonBin = $null
$candidates = @("python3.12", "python3.11", "python3.10", "python3", "python")

foreach ($candidate in $candidates) {
    try {
        $ver = & $candidate -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($ver -match "^3\.(\d+)$") {
            $minor = [int]$Matches[1]
            if ($minor -ge 10) {
                $PythonBin = $candidate
                Write-Ok "Python encontrado: $ver ($candidate)"
                break
            }
        }
    } catch { continue }
}

if (-not $PythonBin) {
    Write-Fail "Python 3.10+ no encontrado. Descárgalo de https://python.org y agrega al PATH."
}

# ── 3. Crear directorios de instalación ──────────────────────────────────────
Write-Info "Creando estructura en $InstallDir..."
$dirs = @(
    $InstallDir,
    "$InstallDir\models",
    "$InstallDir\quarantine",
    "$InstallDir\data\test_set",
    "$InstallDir\logs",
    "$InstallDir\rules"
)
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Ok "Directorios creados."

# ── 4. Copiar código fuente ───────────────────────────────────────────────────
Write-Info "Copiando código desde $SourceDir..."
$excludes = @(".venv", "__pycache__", "*.pyc", ".git", "tests", "deploy")
Get-ChildItem -Path $SourceDir -Exclude $excludes | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $InstallDir -Recurse -Force
}
Write-Ok "Código copiado."

# ── 5. Crear virtualenv e instalar dependencias ───────────────────────────────
Write-Info "Creando entorno virtual en $InstallDir\.venv..."
& $PythonBin -m venv "$InstallDir\.venv"
$VenvPython = "$InstallDir\.venv\Scripts\python.exe"

Write-Info "Actualizando pip..."
& $VenvPython -m pip install --upgrade pip --quiet

$ReqFile = "$InstallDir\requirements.txt"
if (Test-Path $ReqFile) {
    Write-Info "Instalando dependencias desde requirements.txt..."
    & $VenvPython -m pip install -r $ReqFile --quiet
    Write-Ok "Dependencias instaladas."
} else {
    Write-Warn "requirements.txt no encontrado — instalando deps mínimas..."
    & $VenvPython -m pip install `
        fastapi "uvicorn[standard]" psutil onnxruntime `
        pydantic python-multipart supabase --quiet
}

# ── 6. Crear .env si no existe ────────────────────────────────────────────────
$EnvFile = "$InstallDir\.env"
if (-not (Test-Path $EnvFile)) {
    Write-Info "Creando .env de ejemplo..."
    @"
# ShadowNet Defender — Variables de entorno
# EDITAR ANTES DE INICIAR EL SERVICIO

SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key
SUPABASE_JWT_SECRET=your-jwt-secret
SUPABASE_INCIDENTS_TABLE=incidents

N8N_ENABLED=false
N8N_WEBHOOK_PROD=https://your-n8n-instance/webhook/shadownet-malware

ENVIRONMENT=prod
QUARANTINE_DIR=$InstallDir\quarantine
ANALYSIS_TIMEOUT_SECONDS=60
MAX_UPLOAD_MB=50
RATE_LIMIT_SCANS_PER_MINUTE=20
"@ | Set-Content -Path $EnvFile -Encoding UTF8

    Write-Warn "Edita $EnvFile con tus credenciales reales antes de iniciar el servicio."
}

# ── 7. Verificar / descargar NSSM ─────────────────────────────────────────────
Write-Info "Verificando NSSM (Non-Sucking Service Manager)..."
$NssmBin = $null

# Buscar NSSM en PATH o en la carpeta de instalación
foreach ($candidate in @("nssm", "$InstallDir\nssm.exe")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $NssmBin = $candidate
        break
    }
}

if (-not $NssmBin) {
    Write-Info "NSSM no encontrado. Descargando desde GitHub..."
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $nssmZip = "$env:TEMP\nssm.zip"
    $nssmExtract = "$env:TEMP\nssm"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing
        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force

        # Seleccionar arquitectura correcta
        $arch = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
        $nssmExe = Get-ChildItem -Path $nssmExtract -Filter "nssm.exe" -Recurse |
                   Where-Object { $_.FullName -like "*$arch*" } |
                   Select-Object -First 1

        if ($nssmExe) {
            Copy-Item $nssmExe.FullName "$InstallDir\nssm.exe" -Force
            $NssmBin = "$InstallDir\nssm.exe"
            Write-Ok "NSSM descargado e instalado en $NssmBin"
        } else {
            Write-Fail "No se pudo extraer nssm.exe del ZIP."
        }
    } catch {
        Write-Fail "Error descargando NSSM: $_`n`nDescárgalo manualmente de https://nssm.cc y colócalo en $InstallDir\nssm.exe"
    }
} else {
    Write-Ok "NSSM encontrado: $NssmBin"
}

# ── 8. Verificar modelo ONNX ─────────────────────────────────────────────────
$OnnxModel = "$InstallDir\models\best_model.onnx"
if (-not (Test-Path $OnnxModel)) {
    Write-Warn "Modelo ONNX no encontrado en $OnnxModel"
    Write-Warn "Cópialo antes de iniciar el servicio."
}

# ── 9. Registrar e iniciar servicio Windows via NSSM ─────────────────────────
Write-Info "Registrando servicio Windows '$ServiceName'..."

# Eliminar servicio anterior si existe
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Info "Deteniendo y eliminando servicio anterior..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & $NssmBin remove $ServiceName confirm 2>$null
    Start-Sleep -Seconds 2
}

$UvicornArgs = "-m uvicorn backend.app.main:app --host 127.0.0.1 --port $Port --workers 2"

# Registrar el servicio
& $NssmBin install $ServiceName $VenvPython $UvicornArgs
& $NssmBin set $ServiceName AppDirectory $InstallDir
& $NssmBin set $ServiceName DisplayName "ShadowNet Defender"
& $NssmBin set $ServiceName Description "Motor de análisis de malware ShadowNet Defender"
& $NssmBin set $ServiceName Start SERVICE_AUTO_START
& $NssmBin set $ServiceName AppStdout "$InstallDir\logs\stdout.log"
& $NssmBin set $ServiceName AppStderr "$InstallDir\logs\stderr.log"
& $NssmBin set $ServiceName AppRotateFiles 1
& $NssmBin set $ServiceName AppRotateBytes 10485760  # 10 MB

# Variables de entorno desde .env
& $NssmBin set $ServiceName AppEnvironmentExtra "PYTHONPATH=$InstallDir"

Write-Ok "Servicio '$ServiceName' registrado."

# Iniciar el servicio (solo si el modelo está disponible)
if (Test-Path $OnnxModel) {
    Write-Info "Iniciando servicio $ServiceName..."
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -eq "Running") {
        Write-Ok "Servicio '$ServiceName' iniciado correctamente."
    } else {
        Write-Warn "El servicio no arrancó. Estado: $($svc.Status)"
        Write-Warn "Revisa los logs en: $InstallDir\logs\"
    }
} else {
    Write-Warn "Modelo ONNX no encontrado — servicio NO iniciado."
    Write-Warn "Después de copiar los modelos, ejecuta: Start-Service $ServiceName"
}

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  Instalación completada. Próximos pasos:             ║" -ForegroundColor Green
Write-Host "║  1. Edita $InstallDir\.env con tus credenciales   ║" -ForegroundColor Green
Write-Host "║  2. Copia los modelos a $InstallDir\models\       ║" -ForegroundColor Green
Write-Host "║  3. Start-Service $ServiceName                       ║" -ForegroundColor Green
Write-Host "║  4. Verifica: curl http://127.0.0.1:$Port/health     ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
