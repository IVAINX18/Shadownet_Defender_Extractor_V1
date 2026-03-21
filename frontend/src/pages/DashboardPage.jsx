/**
 * pages/DashboardPage.jsx — Vista principal del dashboard.
 *
 * Diseño basado en la referencia:
 * - Scan Center con System Health %
 * - Deep File Scan + Quick System Scan cards
 * - Scan Progress bar
 * - Risk Level / AI Confidence / Threat Type metrics
 * - System metrics (CPU, RAM, Disk, Temp)
 * - Recent Activity sidebar
 */
import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { healthCheck } from '../services/api'

export default function DashboardPage() {
  const navigate = useNavigate()
  const [status, setStatus] = useState({ online: null, data: null })

  useEffect(() => { checkHealth() }, [])

  const checkHealth = async () => {
    try {
      const data = await healthCheck()
      setStatus({ online: true, data: data.data })
    } catch {
      setStatus({ online: false, data: null })
    }
  }

  const healthPct = status.online ? '98.4' : '--'

  return (
    <div style={{ display: 'flex', gap: 20 }} className="animate-fade-in">
      {/* Main content */}
      <div style={{ flex: 1 }}>
        {/* Header: Scan Center + Health */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
              Scan Center
            </h1>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Orchestrate deep-level system inspections using AI neural models.
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              System Health
            </p>
            <p style={{ fontSize: '2.2rem', fontWeight: 700, color: 'var(--green)', lineHeight: 1 }}>
              {healthPct}%
            </p>
          </div>
        </div>

        {/* Scan type cards */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          {/* Deep File Scan */}
          <div
            onClick={() => navigate('/scan')}
            className="card-accent"
            style={{ padding: 28, textAlign: 'center', cursor: 'pointer', transition: 'transform 0.2s' }}
            onMouseEnter={e => e.currentTarget.style.transform = 'translateY(-2px)'}
            onMouseLeave={e => e.currentTarget.style.transform = 'translateY(0)'}
          >
            <div style={{
              width: 48, height: 48, borderRadius: 12,
              background: 'var(--accent-dim)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              margin: '0 auto 12px', fontSize: '1.4rem',
            }}>
              🛡️
            </div>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
              Deep File Scan
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Full system heuristic analysis
            </p>
          </div>

          {/* Quick System Scan */}
          <div
            className="card"
            style={{ padding: 28, textAlign: 'center', cursor: 'pointer', transition: 'transform 0.2s' }}
            onMouseEnter={e => e.currentTarget.style.transform = 'translateY(-2px)'}
            onMouseLeave={e => e.currentTarget.style.transform = 'translateY(0)'}
            onClick={() => navigate('/monitoring')}
          >
            <div style={{
              width: 48, height: 48, borderRadius: 12,
              background: 'rgba(255,255,255,0.05)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              margin: '0 auto 12px', fontSize: '1.4rem',
            }}>
              ⚡
            </div>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
              Quick System Scan
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Critical process evaluation
            </p>
          </div>
        </div>

        {/* Scan Progress */}
        <div className="card" style={{ padding: 16, marginBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>Scan Progress</span>
            <span style={{ fontSize: '0.8rem', color: 'var(--green)', fontWeight: 500 }}>Ready to start</span>
          </div>
        </div>

        {/* Risk / Confidence / Threat metrics */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 20 }}>
          <div className="card" style={{ padding: 16 }}>
            <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
              Risk Level
            </p>
            <p style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--green)' }}>LOW</p>
          </div>
          <div className="card" style={{ padding: 16 }}>
            <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
              AI Confidence
            </p>
            <p style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)' }}>99.98%</p>
          </div>
          <div className="card" style={{ padding: 16 }}>
            <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
              Threat Type
            </p>
            <p style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)' }}>None</p>
          </div>
        </div>

        {/* System metrics */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 12 }}>
          {[
            { icon: '🖥️', label: 'CPU USAGE', value: '24', unit: '%', status: 'Normal', color: 'var(--green)', bars: ['#3fb950','#3fb950','#3fb950','#3fb950','#2a3040','#58a6ff'] },
            { icon: '💾', label: 'RAM USAGE', value: '4.2', unit: 'GB', status: 'Optimized', color: 'var(--green)', bars: ['#d29922','#d29922','#3fb950','#3fb950','#3fb950','#d29922'] },
            { icon: '💿', label: 'DISK LATENCY', value: '12', unit: 'ms', status: 'Healthy', color: 'var(--green)', bars: ['#d29922','#d29922','#3fb950','#d29922','#3fb950','#d29922'] },
            { icon: '🌡️', label: 'SYSTEM TEMP', value: '48', unit: '°C', status: 'Moderate', color: 'var(--yellow)', bars: ['#f85149','#f85149','#f85149','#d29922','#f85149','#f85149'] },
          ].map(m => (
            <div className="card" style={{ padding: 16 }} key={m.label}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                <span style={{ fontSize: '1.2rem' }}>{m.icon}</span>
                <span style={{ fontSize: '0.6rem', fontWeight: 700, color: m.color }}>{m.status}</span>
              </div>
              <p style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                {m.value}<span style={{ fontSize: '0.8rem', fontWeight: 400, color: 'var(--text-muted)' }}>{m.unit}</span>
              </p>
              <p style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: 2 }}>
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

      {/* Right panel: Recent Activity */}
      <div style={{ width: 280, flexShrink: 0 }}>
        <div className="card" style={{ padding: 20 }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            Recent Activity
          </h3>
          <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 16 }}>
            Last 24 hours of security events
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {/* Event 1 */}
            <div className="card" style={{ padding: 14 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--green-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.8rem', flexShrink: 0 }}>✅</div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <p style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)' }}>Deep Scan Completed</p>
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>2h ago</span>
                  </div>
                  <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                    1.2M files analyzed. No threats found.
                  </p>
                  <div style={{ marginTop: 6, display: 'flex', gap: 6 }}>
                    <span className="badge-secure">SECURE</span>
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Duration: 42m 12s</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Event 2 */}
            <div className="card" style={{ padding: 14, borderColor: 'var(--red-border)' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--red-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.8rem', flexShrink: 0 }}>⚠️</div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <p style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)' }}>Malware Blocked</p>
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>5h ago</span>
                  </div>
                  <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                    Trojan.JS.Agent attempt blocked in /temp/sys32
                  </p>
                  <div style={{ marginTop: 6, display: 'flex', gap: 6 }}>
                    <span className="badge-danger">THREAT PREVENTED</span>
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Risk: High</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Event 3 */}
            <div className="card" style={{ padding: 14 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--blue-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.8rem', flexShrink: 0 }}>🔄</div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <p style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)' }}>Database Updated</p>
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>8h ago</span>
                  </div>
                  <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                    Heuristic patterns v.2.45.1 applied successfully.
                  </p>
                </div>
              </div>
            </div>

            {/* Event 4 */}
            <div className="card" style={{ padding: 14 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--green-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.8rem', flexShrink: 0 }}>✅</div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <p style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)' }}>Quick Scan Completed</p>
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>12h ago</span>
                  </div>
                  <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                    Critical directories analyzed. System clean.
                  </p>
                  <div style={{ marginTop: 6, display: 'flex', gap: 6 }}>
                    <span className="badge-secure">SECURE</span>
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Duration: 1m 45s</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <button style={{
            width: '100%', marginTop: 16,
            background: 'transparent', border: 'none',
            color: 'var(--text-muted)', fontSize: '0.75rem',
            fontWeight: 600, cursor: 'pointer',
            textTransform: 'uppercase', letterSpacing: '0.08em',
            padding: '8px 0',
          }}>
            VIEW ALL ACTIVITY
          </button>
        </div>
      </div>
    </div>
  )
}
