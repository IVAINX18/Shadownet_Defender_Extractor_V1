/**
 * electron/preload.js — Bridge seguro entre Electron y la app React.
 *
 * Seguridad:
 *   - contextIsolation: true, nodeIntegration: false en el renderer.
 *   - Solo expongo funciones concretas vía contextBridge (no require('node') en React).
 *
 * Integración React ↔ Electron:
 *   - El renderer llama window.electronAPI.getSystemMetrics() (promesa).
 *   - Esta capa ejecuta módulos Node (os, fs.promises) en el contexto aislado del preload
 *     y devuelve JSON serializable (números, strings, objetos planos).
 *
 * Polling:
 *   - React hace polling cada 2–5 s; cada llamada a getSystemMetrics() mide CPU con un
 *     intervalo interno corto (~450 ms) comparando os.cpus() dos veces (método estándar
 *     sin dependencias nativas extra).
 */

const { contextBridge } = require('electron')
const os = require('os')
const fs = require('fs').promises

/**
 * Mide uso de CPU aproximado del sistema (0–100 %) comparando tiempos idle/total
 * entre dos instantes separados por sampleMs.
 */
function sampleCpuPercent(sampleMs = 450) {
  const cpus1 = os.cpus()
  return new Promise((resolve) => {
    setTimeout(() => {
      try {
        const cpus2 = os.cpus()
        let idleDiff = 0
        let totalDiff = 0
        const n = Math.min(cpus1.length, cpus2.length)
        for (let i = 0; i < n; i++) {
          const a = cpus1[i].times
          const b = cpus2[i].times
          const idle = b.idle - a.idle
          const total =
            b.user -
            a.user +
            (b.nice - a.nice) +
            (b.sys - a.sys) +
            (b.idle - a.idle) +
            (b.irq - a.irq)
          idleDiff += idle
          totalDiff += total
        }
        if (totalDiff <= 0) {
          resolve(0)
          return
        }
        const pct = Math.min(100, Math.max(0, Math.round(100 * (1 - idleDiff / totalDiff))))
        resolve(pct)
      } catch (err) {
        console.error('[preload] sampleCpuPercent:', err)
        resolve(0)
      }
    }, sampleMs)
  })
}

/**
 * Uso de disco en la raíz del volumen del SO (opcional).
 * Usa fs.promises.statfs (Node 18+); si falla, retorno null y el dashboard muestra "—".
 */
async function getDiskUsageSnapshot() {
  try {
    if (typeof fs.statfs !== 'function') return null
    const root = process.platform === 'win32' ? 'C:\\' : '/'
    const s = await fs.statfs(root)
    const bsize = Number(s.bsize)
    const blocks = Number(s.blocks)
    const bavail = Number(s.bavail)
    const total = blocks * bsize
    const avail = bavail * bsize
    const used = total - avail
    if (!Number.isFinite(total) || total <= 0) return null
    return {
      usedBytes: used,
      totalBytes: total,
      usedPercent: Math.min(100, Math.max(0, Math.round((used / total) * 100))),
    }
  } catch (err) {
    console.error('[preload] getDiskUsageSnapshot:', err.message)
    return null
  }
}

async function getSystemMetricsInternal() {
  const cpuPercent = await sampleCpuPercent(450)
  const totalMem = os.totalmem()
  const freeMem = os.freemem()
  const usedMem = totalMem - freeMem
  const ramPercent =
    totalMem > 0 ? Math.min(100, Math.max(0, Math.round((usedMem / totalMem) * 100))) : 0
  const disk = await getDiskUsageSnapshot()

  return {
    cpuPercent,
    ram: {
      usedBytes: usedMem,
      totalBytes: totalMem,
      percent: ramPercent,
    },
    disk,
    hostname: os.hostname(),
  }
}

contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
  isElectron: true,
  getSystemMetrics: () => getSystemMetricsInternal(),
})
