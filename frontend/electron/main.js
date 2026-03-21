/**
 * electron/main.js — Proceso principal de Electron.
 *
 * Levanto la ventana del escritorio y cargo la app React.
 * En desarrollo cargo el dev server de Vite, en producción el build local.
 *
 * Seguridad:
 *   - contextIsolation: true
 *   - nodeIntegration: false
 *   - Preload script para bridge seguro
 */

const { app, BrowserWindow } = require('electron')
const path = require('path')

// Linux: a veces el renderer queda vacío y solo se ve backgroundColor (GPU/Wayland/drivers).
// Desactivar aceleración por hardware lo evita en la mayoría de los casos.
// Para forzar GPU de nuevo: ELECTRON_ENABLE_GPU=1
if (process.platform === 'linux' && process.env.ELECTRON_ENABLE_GPU !== '1') {
  app.disableHardwareAcceleration()
}

// Determino si estoy en desarrollo o producción
const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: 'ShadowNet Defender',
    backgroundColor: '#0a0e1a',
    icon: path.join(__dirname, '../public/vite.svg'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  })

  // En desarrollo cargo el dev server de Vite
  if (isDev) {
    win.loadURL('http://localhost:5173')
    // Abro DevTools en dev
    win.webContents.openDevTools({ mode: 'detach' })
  } else {
    // En producción cargo el build estático
    win.loadFile(path.join(__dirname, '../dist/index.html'))
  }

  // Oculto la barra de menú en producción
  if (!isDev) {
    win.setMenuBarVisibility(false)
  }
}

// Electron ready
app.whenReady().then(() => {
  createWindow()

  // macOS: re-crear ventana si se hace click en el dock
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

// Cerrar la app cuando se cierran todas las ventanas (excepto macOS)
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
