/**
 * pages/HistoryPage.jsx — Monitor de procesos y historial.
 */
import { useState, useEffect } from 'react'
import StatusBadge from '../components/StatusBadge'
import LoadingSpinner from '../components/LoadingSpinner'
import { getRealtime } from '../services/api'
import { Activity, ClipboardList, History as HistoryIcon, RefreshCw, ScrollText } from 'lucide-react'

export default function HistoryPage() {
  const [processes, setProcesses] = useState([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('realtime')

  useEffect(() => { if (activeTab === 'realtime') loadProcesses() }, [activeTab])

  const loadProcesses = async () => {
    setLoading(true)
    try {
      const response = await getRealtime()
      setProcesses(response.data || [])
    } catch (err) { console.error('Failed:', err) }
    finally { setLoading(false) }
  }

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }} className="animate-fade-in">
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 10 }}>
          <ClipboardList size={26} color="var(--accent)" /> Monitor & History
        </h1>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          Real-time process monitoring and scan history
        </p>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, alignItems: 'center' }}>
        {['realtime', 'history'].map((tab) => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            style={{
              padding: '8px 16px', borderRadius: 8, border: 'none',
              fontSize: '0.8rem', fontWeight: 500, cursor: 'pointer',
              background: activeTab === tab ? 'var(--accent)' : 'var(--bg-card)',
              color: activeTab === tab ? 'white' : 'var(--text-secondary)',
              transition: 'all 0.15s', display: 'flex', alignItems: 'center', gap: 6,
            }}>
            {tab === 'realtime' ? <><Activity size={16} /> Real-time</> : <><HistoryIcon size={16} /> History</>}
          </button>
        ))}
        {activeTab === 'realtime' && (
          <button onClick={loadProcesses} className="btn-secondary" style={{ marginLeft: 'auto', fontSize: '0.75rem', padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 6 }}>
            <RefreshCw size={14} /> Refresh
          </button>
        )}
      </div>

      {activeTab === 'realtime' && (
        <>
          {loading ? (
            <div className="card" style={{ padding: 40, textAlign: 'center' }}>
              <LoadingSpinner size="lg" text="Loading processes..." />
            </div>
          ) : (
            <div className="card" style={{ overflow: 'hidden' }}>
              <table style={{ width: '100%', fontSize: '0.8rem', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['PID', 'Name', 'CPU %', 'Mem %', 'RSS MB', 'Risk'].map(h => (
                      <th key={h} style={{ textAlign: 'left', padding: '10px 14px', fontSize: '0.65rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {processes.slice(0, 25).map((p, i) => (
                    <tr key={p.pid || i} style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.15s' }}
                      onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-card-hover)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                      <td style={{ padding: '8px 14px', color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.7rem' }}>{p.pid}</td>
                      <td style={{ padding: '8px 14px', color: 'var(--text-primary)' }}>{p.name}</td>
                      <td style={{ padding: '8px 14px', color: 'var(--text-secondary)' }}>
                        {(p.cpu_percent ?? p.cpu ?? 0).toFixed(1)}
                      </td>
                      <td style={{ padding: '8px 14px', color: 'var(--text-secondary)' }}>
                        {(p.memory_percent ?? p.memory ?? 0).toFixed(1)}
                      </td>
                      <td style={{ padding: '8px 14px', color: 'var(--text-secondary)', fontFamily: 'monospace', fontSize: '0.7rem' }}>
                        {p.memory_mb != null ? p.memory_mb.toFixed(1) : '—'}
                      </td>
                      <td style={{ padding: '8px 14px' }}>
                        <StatusBadge
                          result={p.risk_level === 'suspicious' ? 'suspicious' : 'benign'}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {processes.length === 0 && (
                <p style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 30 }}>No processes found</p>
              )}
            </div>
          )}
        </>
      )}

      {activeTab === 'history' && (
        <div className="card" style={{ padding: 40, textAlign: 'center' }}>
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
            <ScrollText size={48} color="var(--text-muted)" strokeWidth={1} />
          </div>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8 }}>Scan History</h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', maxWidth: 350, margin: '0 auto' }}>
            Your past scan results are stored in Supabase. Use the Scan page to analyze files — results are automatically saved.
          </p>
        </div>
      )}
    </div>
  )
}
