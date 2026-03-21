/**
 * electron/preload.js — Bridge seguro entre Electron y la app React.
 *
 * Uso contextBridge para exponer solo lo necesario.
 * Por ahora expongo info básica del entorno.
 */

const { contextBridge } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
  isElectron: true,
})
