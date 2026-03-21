/**
 * pages/DashboardPage.jsx — Dashboard con datos reales únicamente.
 *
 * Fuentes de datos:
 *   - Backend: GET /health (estado API + modelo ML + max_upload_mb vía hook useDashboardBackend).
 *   - Backend: GET /scan/realtime (conteo y tabla resumida de procesos; psutil en servidor).
 *   - Backend: GET /scan/recent (actividad reciente desde Supabase; vacío si no hay filas).
 *   - Electron: window.electronAPI.getSystemMetrics() vía useElectronSystemMetrics (CPU/RAM/disco local).
 *
 * Polling: intervalos definidos en los hooks (≈3–15 s); no hay números estáticos inventados.
 */
import { useNavigate } from 'react-router-dom'
import { useDashboardBackend } from '../hooks/useDashboardBackend'
import { useElectronSystemMetrics } from '../hooks/useElectronSystemMetrics'
import {
  aggregateRecentScans,
  metricBarsForPercent,
  formatBytes,
  timeAgoLabel,
} from '../utils/dashboardStats'

function modelLabel(model) {
  if (model === 'loaded') return { text: 'Cargado', color: 'var(--green)' }
  if (model === 'not_loaded') return { text: 'No cargado', color: 'var(--yellow)' }
  if (model === 'error') return { text: 'Error', color: 'var(--red)' }
  return { text: '—', color: 'var(--text-muted)' }
}

function loadStatusLabel(cpuPct) {
  if (!Number.isFinite(cpuPct)) return '—'
  if (cpuPct >= 85) return 'Alto'
  if (cpuPct >= 55) return 'Moderado'
  return 'Normal'
}

function loadStatusColor(cpuPct) {
  if (!Number.isFinite(cpuPct)) return 'var(--text-muted)'
  if (cpuPct >= 85) return 'var(--red)'
  if (cpuPct >= 55) return 'var(--yellow)'
  return 'var(--green)'
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const { health, realtime, recent } = useDashboardBackend()
  const { metrics, error: metricsError, isElectron } = useElectronSystemMetrics()

  const agg = aggregateRecentScans(recent.rows)
  const ml = modelLabel(health.data?.model)
  const processCount = realtime.processes.length

  const cpuPct = metrics?.cpuPercent
  const ramPct = metrics?.ram?.percent
  const diskPct = metrics?.disk?.usedPercent

  const systemCards = [
    {
      key: 'cpu',
      icon: '🖥️',
      label: 'CPU USAGE (local)',
      value: isElectron && Number.isFinite(cpuPct) ? String(cpuPct) : '—',
      unit: Number.isFinite(cpuPct) ? '%' : '',
      status: isElectron ? loadStatusLabel(cpuPct) : 'N/A',
      statusColor: isElectron ? loadStatusColor(cpuPct) : 'var(--text-muted)',
      bars: isElectron && Number.isFinite(cpuPct) ? metricBarsForPercent(cpuPct) : Array(6).fill('#2a3040'),
    },
    {
      key: 'ram',
      icon: '💾',
      label: 'RAM USAGE (local)',
      value:
        isElectron && metrics?.ram
          ? formatBytes(metrics.ram.usedBytes)
          : '—',
      unit: '',
      status: isElectron && Number.isFinite(ramPct) ? `${ramPct}%` : '—',
      statusColor: isElectron ? loadStatusColor(ramPct) : 'var(--text-muted)',
      bars: isElectron && Number.isFinite(ramPct) ? metricBarsForPercent(ramPct) : Array(6).fill('#2a3040'),
    },
    {
      key: 'disk',
      icon: '💿',
      label: 'DISK USAGE (local)',
      value:
        isElectron && metrics?.disk
          ? `${metrics.disk.usedPercent}%`
          : '—',
      unit: '',
      status:
        isElectron && metrics?.disk
          ? `${formatBytes(metrics.disk.usedBytes)} / ${formatBytes(metrics.disk.totalBytes)}`
          : 'No disponible',
      statusColor: 'var(--text-secondary)',
      bars:
        isElectron && Number.isFinite(diskPct)
          ? metricBarsForPercent(diskPct)
          : Array(6).fill('#2a3040'),
    },
    {
      key: 'api',
      icon: '☁️',
      label: 'PROCESOS (API)',
      value: health.online ? String(processCount) : '—',
      unit: health.online ? ' activos' : '',
      status: realtime.error ? 'Error API' : health.online ? 'Desde /scan/realtime' : '—',
      statusColor: realtime.error ? 'var(--red)' : 'var(--green)',
      bars: Array(6).fill('#2a3040'),
    },
  ]

  return (
    <div style={{ display: 'flex', gap: 20 }} className="animate-fade-in">
      <div style={{ flex: 1 }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            marginBottom: 20,
            flexWrap: 'wrap',
            gap: 16,
          }}
        >
          <div>
            <h1
              style={{
                fontSize: '1.5rem',
                fontWeight: 700,
                color: 'var(--text-primary)',
                marginBottom: 4,
              }}
            >
              Scan Center
            </h1>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Estado en vivo del backend, del modelo y del equipo (Electron).
            </p>
          </div>
          <div
            style={{
              textAlign: 'right',
              minWidth: 200,
              padding: '12px 16px',
              borderRadius: 12,
              border: '1px solid var(--border)',
              background: 'var(--bg-card)',
            }}
          >
            <p
              style={{
                fontSize: '0.65rem',
                color: 'var(--text-muted)',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: 8,
              }}
            >
              Estado del sistema
            </p>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)', marginBottom: 6 }}>
              <span style={{ color: 'var(--text-muted)' }}>Backend: </span>
              <span style={{ fontWeight: 600, color: health.online ? 'var(--green)' : 'var(--red)' }}>
                {health.online === null ? '…' : health.online ? 'En línea' : 'Desconectado'}
              </span>
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)', marginBottom: 6 }}>
              <span style={{ color: 'var(--text-muted)' }}>Modelo ML: </span>
              <span style={{ fontWeight: 600, color: ml.color }}>{ml.text}</span>
            </div>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
              Último chequeo: {health.checkedAt ? timeAgoLabel(health.checkedAt) : '—'}
            </div>
            {health.error && (
              <div style={{ fontSize: '0.72rem', color: 'var(--red)', marginTop: 8 }}>
                {health.error}
              </div>
            )}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          <div
            onClick={() => navigate('/scan')}
            className="card-accent"
            style={{
              padding: 28,
              textAlign: 'center',
              cursor: 'pointer',
              transition: 'transform 0.2s',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)'
            }}
          >
            <div
              style={{
                width: 48,
                height: 48,
                borderRadius: 12,
                background: 'var(--accent-dim)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 12px',
                fontSize: '1.4rem',
              }}
            >
              🛡️
            </div>
            <h3
              style={{
                fontSize: '1rem',
                fontWeight: 600,
                color: 'var(--text-primary)',
                marginBottom: 4,
              }}
            >
              Deep File Scan
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Análisis ML en el backend (límite {health.data?.max_upload_mb ?? '—'} MB)
            </p>
          </div>

          <div
            className="card"
            style={{
              padding: 28,
              textAlign: 'center',
              cursor: 'pointer',
              transition: 'transform 0.2s',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)'
            }}
            onClick={() => navigate('/history')}
          >
            <div
              style={{
                width: 48,
                height: 48,
                borderRadius: 12,
                background: 'rgba(255,255,255,0.05)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 12px',
                fontSize: '1.4rem',
              }}
            >
              ⚡
            </div>
            <h3
              style={{
                fontSize: '1rem',
                fontWeight: 600,
                color: 'var(--text-primary)',
                marginBottom: 4,
              }}
            >
              Quick System Scan
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Procesos en tiempo real (servidor)
            </p>
          </div>
        </div>

        <div className="card" style={{ padding: 16, marginBottom: 20 }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: 8,
            }}
          >
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Actividad de procesos (API)
            </span>
            <span
              style={{
                fontSize: '0.8rem',
                fontWeight: 500,
                color: realtime.error ? 'var(--red)' : 'var(--text-secondary)',
              }}
            >
              {health.online === false
                ? 'Sin conexión al backend'
                : realtime.error
                  ? realtime.error
                  : `${processCount} procesos en la última muestra`}
            </span>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 20 }}>
          <div className="card" style={{ padding: 16 }}>
            <p
              style={{
                fontSize: '0.65rem',
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: 6,
              }}
            >
              Risk Level (últimos escaneos)
            </p>
            <p
              style={{
                fontSize: '1.3rem',
                fontWeight: 700,
                color:
                  agg.riskLabel === 'HIGH'
                    ? 'var(--red)'
                    : agg.riskLabel === 'MEDIUM'
                      ? 'var(--yellow)'
                      : agg.hasData
                        ? 'var(--green)'
                        : 'var(--text-muted)',
              }}
            >
              {agg.riskLabel}
            </p>
          </div>
          <div className="card" style={{ padding: 16 }}>
            <p
              style={{
                fontSize: '0.65rem',
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: 6,
              }}
            >
              AI confidence (promedio)
            </p>
            <p style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {agg.avgConfidenceLabel}
            </p>
          </div>
          <div className="card" style={{ padding: 16 }}>
            <p
              style={{
                fontSize: '0.65rem',
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: 6,
              }}
            >
              Threat summary
            </p>
            <p style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {agg.threatSummary}
            </p>
          </div>
        </div>

        {!isElectron && (
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 12 }}>
            CPU/RAM/disco local: solo disponible en la app Electron (preload seguro).
          </p>
        )}
        {isElectron && metricsError && (
          <p style={{ fontSize: '0.75rem', color: 'var(--yellow)', marginBottom: 12 }}>
            Métricas locales: {metricsError}
          </p>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
          {systemCards.map((m) => (
            <div className="card" style={{ padding: 16 }} key={m.key}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: 10,
                }}
              >
                <span style={{ fontSize: '1.2rem' }}>{m.icon}</span>
                <span style={{ fontSize: '0.6rem', fontWeight: 700, color: m.statusColor }}>
                  {m.status}
                </span>
              </div>
              <p style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                {m.value}
                <span style={{ fontSize: '0.8rem', fontWeight: 400, color: 'var(--text-muted)' }}>
                  {m.unit}
                </span>
              </p>
              <p
                style={{
                  fontSize: '0.6rem',
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  marginTop: 2,
                }}
              >
                {m.label}
              </p>
              <div className="metric-bars">
                {m.bars.map((c, i) => (
                  <div key={i} className="metric-bar" style={{ background: c }} />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ width: 280, flexShrink: 0 }}>
        <div className="card" style={{ padding: 20 }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            Recent Activity
          </h3>
          <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 16 }}>
            Últimos escaneos guardados (Supabase)
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {recent.loading && recent.rows.length === 0 && (
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Cargando…</p>
            )}
            {!recent.loading && recent.rows.length === 0 && (
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {health.online === false
                  ? 'Conecta el backend para ver historial.'
                  : 'No hay escaneos recientes en el servidor.'}
              </p>
            )}
            {recent.rows.map((row, idx) => {
              const result = row.result || '—'
              const isBad = result === 'malicious'
              const isWarn = result === 'suspicious'
              return (
                <div
                  className="card"
                  style={{
                    padding: 14,
                    borderColor: isBad ? 'var(--red-border)' : undefined,
                  }}
                  key={`${row.file_name}-${idx}`}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                    <div
                      style={{
                        width: 28,
                        height: 28,
                        borderRadius: '50%',
                        background: isBad ? 'var(--red-bg)' : isWarn ? 'var(--yellow-bg)' : 'var(--green-bg)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: '0.8rem',
                        flexShrink: 0,
                      }}
                    >
                      {isBad ? '⚠️' : isWarn ? '⚡' : '✅'}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                        <p
                          style={{
                            fontSize: '0.78rem',
                            fontWeight: 600,
                            color: 'var(--text-primary)',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {row.file_name || 'archivo'}
                        </p>
                        <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', flexShrink: 0 }}>
                          {timeAgoLabel(row.created_at)}
                        </span>
                      </div>
                      <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                        Resultado: <strong>{result}</strong>
                        {row.score != null && typeof row.score === 'number' && (
                          <> · score {row.score <= 1 ? `${(row.score * 100).toFixed(1)}%` : row.score}</>
                        )}
                      </p>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>

          <button
            type="button"
            onClick={() => navigate('/history')}
            style={{
              width: '100%',
              marginTop: 16,
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              fontSize: '0.75rem',
              fontWeight: 600,
              cursor: 'pointer',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              padding: '8px 0',
            }}
          >
            VIEW ALL ACTIVITY
          </button>
        </div>
      </div>
    </div>
  )
}
