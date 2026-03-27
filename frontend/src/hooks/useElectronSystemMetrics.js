/**
 * useElectronSystemMetrics — Polling de CPU/RAM/disco vía preload (Electron).
 *
 * En navegador puro no existe window.electronAPI.getSystemMetrics; isElectron queda false
 * y metrics null (el dashboard muestra "—" / mensaje de escritorio).
 */
import { useState, useEffect } from 'react'

const POLL_MS = 3500

export function useElectronSystemMetrics() {
  const [metrics, setMetrics] = useState(null)
  const [error, setError] = useState(null)
  const [isElectron, setIsElectron] = useState(false)

  useEffect(() => {
    const api = typeof window !== 'undefined' ? window.electronAPI : null
    if (!api?.getSystemMetrics) {
      setIsElectron(false)
      return undefined
    }

    setIsElectron(true)
    let cancelled = false

    const tick = async () => {
      try {
        const m = await api.getSystemMetrics()
        if (!cancelled) {
          setMetrics(m)
          setError(null)
        }
      } catch (e) {
        console.error('[useElectronSystemMetrics]', e)
        if (!cancelled) setError(e?.message || String(e))
      }
    }

    tick()
    const id = setInterval(tick, POLL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  return { metrics, error, isElectron }
}
