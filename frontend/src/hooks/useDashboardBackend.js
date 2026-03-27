/**
 * useDashboardBackend — Polling de /health, /scan/realtime y /scan/recent.
 *
 * - health: cada ~8 s; si falla, online=false y el dashboard muestra "Backend desconectado"
 *   sin lanzar errores a la UI.
 * - realtime / recent: solo cuando health.online === true para no spamear 401 si la sesión
 *   depende del backend (el token sigue yendo en Axios).
 */
import { useState, useEffect, useCallback } from 'react'
import { healthCheck, getRealtime, getRecentScans } from '../services/api'

const HEALTH_MS = 8000
const REALTIME_MS = 4000
const RECENT_MS = 15000

export function useDashboardBackend() {
  const [health, setHealth] = useState({
    online: null,
    data: null,
    error: null,
    checkedAt: null,
  })
  const [realtime, setRealtime] = useState({
    processes: [],
    error: null,
    loading: false,
  })
  const [recent, setRecent] = useState({
    rows: [],
    error: null,
    loading: false,
  })

  const fetchHealth = useCallback(async () => {
    try {
      const body = await healthCheck()
      setHealth({
        online: true,
        data: body.data ?? null,
        error: null,
        checkedAt: new Date().toISOString(),
      })
    } catch {
      setHealth({
        online: false,
        data: null,
        error: 'Backend desconectado',
        checkedAt: new Date().toISOString(),
      })
    }
  }, [])

  const fetchRealtime = useCallback(async () => {
    setRealtime((s) => ({ ...s, loading: true }))
    try {
      const body = await getRealtime()
      setRealtime({
        processes: Array.isArray(body.data) ? body.data : [],
        error: null,
        loading: false,
      })
    } catch (e) {
      const msg =
        e?.response?.data?.message || e?.message || 'No se pudo obtener procesos'
      setRealtime((s) => ({
        ...s,
        processes: [],
        error: msg,
        loading: false,
      }))
    }
  }, [])

  const fetchRecent = useCallback(async () => {
    setRecent((s) => ({ ...s, loading: true }))
    try {
      const body = await getRecentScans(8)
      setRecent({
        rows: Array.isArray(body.data) ? body.data : [],
        error: null,
        loading: false,
      })
    } catch {
      setRecent({ rows: [], error: null, loading: false })
    }
  }, [])

  useEffect(() => {
    fetchHealth()
    const id = setInterval(fetchHealth, HEALTH_MS)
    return () => clearInterval(id)
  }, [fetchHealth])

  useEffect(() => {
    if (health.online !== true) return undefined
    fetchRealtime()
    fetchRecent()
    const idR = setInterval(fetchRealtime, REALTIME_MS)
    const idRec = setInterval(fetchRecent, RECENT_MS)
    return () => {
      clearInterval(idR)
      clearInterval(idRec)
    }
  }, [health.online, fetchRealtime, fetchRecent])

  return {
    health,
    realtime,
    recent,
    refetchHealth: fetchHealth,
  }
}
