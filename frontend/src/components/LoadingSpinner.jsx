/**
 * components/LoadingSpinner.jsx — Indicador de carga animado.
 */
export default function LoadingSpinner({ size = 'md', text = '' }) {
  const sizes = { sm: 20, md: 32, lg: 48 }
  const s = sizes[size] || sizes.md

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
      <div style={{
        width: s, height: s,
        border: '2px solid var(--border)',
        borderTopColor: 'var(--accent)',
        borderRadius: '50%',
        animation: 'spin 0.8s linear infinite',
      }} />
      {text && <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{text}</p>}
    </div>
  )
}
