/**
 * components/Sidebar.jsx — Barra lateral estilo dashboard de ciberseguridad.
 *
 * Diseño basado en la referencia: logo arriba, navegación con iconos,
 * sección de usuario abajo. Fondo oscuro con bordes sutiles.
 */
import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Shield, History, Activity, LogOut } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scan', icon: Shield, label: 'Scans' },
  { to: '/history', icon: History, label: 'History' },
  { to: '/monitoring', icon: Activity, label: 'Monitoring' },
]

export default function Sidebar() {
  const { user, logout } = useAuth()

  return (
    <aside style={{
      width: 240,
      background: 'var(--bg-sidebar)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      position: 'sticky',
      top: 0,
    }}>
      {/* Logo */}
      <div style={{
        padding: '28px 20px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        borderBottom: '1px solid var(--border)',
      }}>
        <img
          src="/logo-vector.png"
          alt="ShadowNet Defender"
          style={{ width: 120, height: 'auto', objectFit: 'contain', marginBottom: 6 }}
        />
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '16px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              padding: '12px 16px',
              borderRadius: 8,
              fontSize: '0.85rem',
              fontWeight: isActive ? 500 : 400,
              textDecoration: 'none',
              transition: 'all 0.2s ease',
              background: isActive ? 'var(--accent-dim)' : 'transparent',
              color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
              borderLeft: isActive ? '3px solid var(--accent)' : '3px solid transparent',
            })}
          >
            <Icon size={18} strokeWidth={2} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* User + logout */}
      <div style={{
        padding: '20px 16px',
        borderTop: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
          <div style={{
            width: 36, height: 36, borderRadius: '50%',
            background: 'linear-gradient(135deg, #1e293b, #0f172a)',
            border: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--text-primary)', fontSize: '0.85rem', fontWeight: 600,
          }}>
            {user?.email?.[0]?.toUpperCase() || 'U'}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <p style={{
              fontSize: '0.8rem', fontWeight: 500,
              color: 'var(--text-primary)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {user?.email?.split('@')[0] || 'User'}
            </p>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 2 }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)' }} />
              <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Systems Online</p>
            </div>
          </div>
        </div>
        <button 
          onClick={logout} 
          className="btn-secondary" 
          style={{ width: '100%', fontSize: '0.75rem', padding: '8px 12px', display: 'flex', justifyContent: 'center', gap: 6 }}
        >
          <LogOut size={14} />
          Sign Out
        </button>
      </div>
    </aside>
  )
}
