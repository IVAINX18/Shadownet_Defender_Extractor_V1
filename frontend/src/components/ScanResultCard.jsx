/**
 * components/ScanResultCard.jsx — Tarjeta de resultado de escaneo.
 */
import { FileText, RefreshCw, Bot, Cpu, Cloud, Zap } from 'lucide-react'
import StatusBadge from './StatusBadge'

/**
 * Indicador del proveedor que resolvió la explicación en la cascada
 * Tri-Fallover (groq -> gemini -> template). El backend lo expone en
 * response.data.llm.provider; el frontend jamás ve API keys, solo el nombre.
 */
const PROVIDER_META = {
  groq: { label: 'Groq · gpt-oss-20b', icon: Zap, color: 'var(--orange, #f97316)' },
  gemini: { label: 'Gemini · flash-lite', icon: Cloud, color: 'var(--blue, #3b82f6)' },
  template: { label: 'Offline · Nativo', icon: Cpu, color: 'var(--text-muted)' },
  ollama: { label: 'Ollama · Local', icon: Cpu, color: 'var(--green)' },
}

function ProviderPill({ llmMeta }) {
  if (!llmMeta?.provider) return null
  const meta = PROVIDER_META[llmMeta.provider] || { label: llmMeta.provider, icon: Bot, color: 'var(--text-muted)' }
  const Icon = meta.icon
  return (
    <span
      title={`${meta.label}${llmMeta.model ? ` (${llmMeta.model})` : ''}${llmMeta.status && llmMeta.status !== 'ok' ? ` — ${llmMeta.status}` : ''}`}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        fontSize: '0.6rem', fontWeight: 600, color: meta.color,
        border: `1px solid ${meta.color}`, borderRadius: 999, padding: '2px 8px',
        textTransform: 'uppercase', letterSpacing: '0.04em',
      }}
    >
      <Icon size={10} /> {meta.label}
    </span>
  )
}

export default function ScanResultCard({ result, onExplain, explaining = false }) {
  if (!result) return null

  const riskColors = { low: 'var(--green)', medium: 'var(--yellow)', high: 'var(--red)' }

  return (
    <div className="card animate-slide-up" style={{ padding: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 10,
            background: 'var(--bg-input)', border: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--accent)'
          }}><FileText size={20} strokeWidth={2} /></div>
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
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
          }}>
            <span>AI Explanation</span>
            <ProviderPill llmMeta={result.llmMeta} />
          </h4>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
            {result.explanation}
          </p>
        </div>
      ) : onExplain ? (
        <button
          onClick={() => onExplain(result)}
          disabled={explaining}
          className="btn-secondary"
          style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
        >
          {explaining ? (
            <><RefreshCw size={16} className="animate-spin" /> Generating explanation...</>
          ) : (
            <><Bot size={16} /> Get AI Explanation</>
          )}
        </button>
      ) : null}
    </div>
  )
}
