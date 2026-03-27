/**
 * components/StatusBadge.jsx — Badge de estado con color semántico.
 */
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react'

export default function StatusBadge({ result }) {
  const config = {
    benign: { cls: 'badge-secure', label: 'Benign', Icon: ShieldCheck },
    suspicious: { cls: 'badge-warning', label: 'Suspicious', Icon: ShieldAlert },
    malicious: { cls: 'badge-danger', label: 'Malicious', Icon: AlertTriangle },
  }
  const c = config[result] || config.suspicious
  
  const IconComponent = c.Icon

  return (
    <span className={c.cls}>
      <IconComponent size={14} strokeWidth={2.5} />
      {c.label}
    </span>
  )
}
