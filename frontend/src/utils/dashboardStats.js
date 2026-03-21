/**
 * dashboardStats.js — Agregaciones sobre datos reales del backend (sin valores inventados).
 *
 * Risk / confidence / threat se derivan únicamente de filas devueltas por GET /scan/recent.
 * Si no hay filas, se devuelven placeholders explícitos ("Sin datos").
 */

/**
 * @param {Array<Record<string, unknown>>} rows
 */
export function aggregateRecentScans(rows) {
  if (!rows?.length) {
    return {
      riskLabel: '—',
      avgConfidenceLabel: '—',
      threatSummary: 'Sin datos',
      hasData: false,
    }
  }

  const scores = rows
    .map((r) => Number(r.score))
    .filter((n) => !Number.isNaN(n))

  let avgConfidenceLabel = '—'
  if (scores.length) {
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length
    const pct = avg <= 1 ? avg * 100 : avg
    avgConfidenceLabel = `${pct.toFixed(1)}%`
  }

  let threatSummary = 'Benign'
  if (rows.some((r) => r.result === 'malicious')) threatSummary = 'Malicious'
  else if (rows.some((r) => r.result === 'suspicious')) threatSummary = 'Suspicious'

  let riskLabel = 'LOW'
  if (rows.some((r) => r.result === 'malicious' || String(r.risk_level).toLowerCase() === 'high'))
    riskLabel = 'HIGH'
  else if (
    rows.some((r) => r.result === 'suspicious' || String(r.risk_level).toLowerCase() === 'medium')
  )
    riskLabel = 'MEDIUM'

  return {
    riskLabel,
    avgConfidenceLabel,
    threatSummary,
    hasData: true,
  }
}

/**
 * Barras de métrica 0–100 % para visualización (colores según umbrales reales).
 */
export function metricBarsForPercent(pct) {
  const p = Number.isFinite(pct) ? Math.min(100, Math.max(0, pct)) : 0
  const filled = Math.round((p / 100) * 6)
  const color =
    p >= 85 ? 'var(--red)' : p >= 65 ? 'var(--yellow)' : 'var(--green)'
  return Array.from({ length: 6 }, (_, i) => (i < filled ? color : '#2a3040'))
}

/**
 * Etiqueta breve para timestamps ISO (actividad reciente).
 */
export function timeAgoLabel(iso) {
  if (!iso) return ''
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return ''
  const sec = Math.floor((Date.now() - t) / 1000)
  if (sec < 45) return 'ahora'
  if (sec < 3600) return `hace ${Math.floor(sec / 60)} min`
  if (sec < 86400) return `hace ${Math.floor(sec / 3600)} h`
  return `hace ${Math.floor(sec / 86400)} d`
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = bytes
  let i = 0
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`
}
