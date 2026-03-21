/**
 * components/ScanResultCard.jsx — Tarjeta de resultado de escaneo.
 */
import StatusBadge from './StatusBadge'

export default function ScanResultCard({ result, onExplain, explaining = false }) {
  if (!result) return null

  const riskColors = { low: 'var(--green)', medium: 'var(--yellow)', high: 'var(--red)' }

  return (
    <div className="card animate-slide-up" style={{ padding: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 40, height: 40, borderRadius: 10,
            background: 'var(--bg-input)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '1.2rem',
          }}>📄</div>
          <div>
            <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              {result.file_name}
            </h3>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              {result.scan_time} • {result.analysis_type || 'unknown'}
            </p>
          </div>
        </div>
        <StatusBadge result={result.result} />
      </div>

      {/* Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 16 }}>
        <div className="card" style={{ padding: 12, textAlign: 'center' }}>
          <p style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase' }}>Confidence</p>
          <p style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {(result.confidence * 100).toFixed(1)}%
          </p>
        </div>
        <div className="card" style={{ padding: 12, textAlign: 'center' }}>
          <p style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase' }}>Risk</p>
          <p style={{ fontSize: '1.2rem', fontWeight: 700, color: riskColors[result.risk_level] || 'var(--text-primary)' }}>
            {result.risk_level?.toUpperCase()}
          </p>
        </div>
        <div className="card" style={{ padding: 12, textAlign: 'center' }}>
          <p style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase' }}>Type</p>
          <p style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--accent)' }}>
            {result.analysis_type === 'pe' ? 'PE' : 'NON-PE'}
          </p>
        </div>
      </div>

      {/* Explanation */}
      {result.explanation ? (
        <div style={{
          background: 'var(--bg-input)', borderRadius: 8, padding: 16, marginBottom: 12,
        }}>
          <h4 style={{
            fontSize: '0.65rem', fontWeight: 600, color: 'var(--accent)',
            marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em',
          }}>AI Explanation</h4>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
            {result.explanation}
          </p>
        </div>
      ) : onExplain ? (
        <button
          onClick={() => onExplain(result)}
          disabled={explaining}
          className="btn-secondary"
          style={{ width: '100%' }}
        >
          {explaining ? '🔄 Generating explanation...' : '🤖 Get AI Explanation'}
        </button>
      ) : null}
    </div>
  )
}
