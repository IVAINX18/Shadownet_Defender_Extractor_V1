/**
 * components/StatusBadge.jsx — Badge de estado con color semántico.
 */
export default function StatusBadge({ result }) {
  const config = {
    benign: { cls: 'badge-secure', label: 'Benign', icon: '🛡️' },
    suspicious: { cls: 'badge-warning', label: 'Suspicious', icon: '⚠️' },
    malicious: { cls: 'badge-danger', label: 'Malicious', icon: '🔴' },
  }
  const c = config[result] || config.suspicious

  return (
    <span className={c.cls}>
      <span>{c.icon}</span>
      {c.label}
    </span>
  )
}
