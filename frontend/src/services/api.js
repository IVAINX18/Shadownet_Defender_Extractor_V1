/**
 * services/api.js — Capa de comunicación con el backend FastAPI.
 *
 * Centralizo todas las llamadas HTTP en un solo módulo.
 * Uso Axios con interceptor para inyectar el token JWT
 * automáticamente en cada request.
 */

import axios from 'axios'

// Leo la URL del backend desde env (default: localhost:8000)
const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

// Instancia Axios con configuración base
const api = axios.create({
  baseURL: API_URL,
  timeout: 120000, // 120s — el LLM puede tardar hasta 60s
  headers: {
    'Accept': 'application/json',
  },
})

// --- Token management ---
// Guardo referencia al token para inyectarlo en cada request.
// Se actualiza desde el AuthContext.
let _token = null

export function setApiToken(token) {
  _token = token
}

// Interceptor: inyecto el token Bearer en cada request
api.interceptors.request.use((config) => {
  if (_token) {
    config.headers.Authorization = `Bearer ${_token}`
  }
  return config
})

// Interceptor de respuesta: extraigo errors de forma uniforme
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Si es 401, el token expiró
    if (error.response?.status === 401) {
      console.warn('[API] Token expirado o inválido')
    }
    return Promise.reject(error)
  }
)

// ====================================================================
// API Functions
// ====================================================================

/**
 * Verifica que el backend esté activo.
 * GET /health
 */
export async function healthCheck() {
  const { data } = await api.get('/health')
  return data
}

/**
 * Escaneo de un archivo individual.
 * POST /scan/file (multipart/form-data)
 */
export async function scanFile(file) {
  const formData = new FormData()
  formData.append('file', file)

  const { data } = await api.post('/scan/file', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 60000,
  })
  return data
}

/**
 * Escaneo de múltiples archivos.
 * POST /scan/multiple (multipart/form-data)
 */
export async function scanMultiple(files) {
  const formData = new FormData()
  files.forEach((file) => formData.append('files', file))

  const { data } = await api.post('/scan/multiple', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 120000,
  })
  return data
}

/**
 * Solicita explicación LLM para un resultado de escaneo.
 * POST /analysis/explain
 */
export async function explainResult(scanResult, provider = 'ollama') {
  const { data } = await api.post('/analysis/explain', {
    scan_result: scanResult,
    provider,
  })
  return data
}

/**
 * Obtiene la lista de procesos activos.
 * GET /scan/realtime
 */
export async function getRealtime() {
  const { data } = await api.get('/scan/realtime')
  return data
}

/**
 * Verifica si el backend está accesible.
 * Retorna true/false sin lanzar excepciones.
 */
export async function isBackendOnline() {
  try {
    await api.get('/health', { timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export default api
