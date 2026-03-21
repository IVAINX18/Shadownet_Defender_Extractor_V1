/**
 * components/Sidebar.jsx — Barra lateral estilo dashboard de ciberseguridad.
 *
 * Diseño basado en la referencia: logo arriba, navegación con iconos,
 * sección de usuario abajo. Fondo oscuro con bordes sutiles.
 */
import { NavLink } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const navItems = [
  { to: '/dashboard', icon: '⊞', label: 'Dashboard' },
  { to: '/scan', icon: '◎', label: 'Scans' },
  { to: '/history', icon: '☰', label: 'History' },
  { to: '/monitoring', icon: '⚙', label: 'Monitoring' },
]

export default function Sidebar() {
  const { user, logout } = useAuth()

  return (
    <aside style={{
      width: 220,
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
        padding: '24px 20px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        borderBottom: '1px solid var(--border)',
      }}>
        <img
          src="/logo-light.png"
          alt="ShadowNet Defender"
          style={{ width: 90, height: 90, objectFit: 'contain', marginBottom: 4 }}
        />
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '12px 10px', display: 'flex', flexDirection: 'column', gap: 2 }}>
        {navItems.map(({ to, icon, label }) => (
          <NavLink
            key={to}
            to={to}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              padding: '10px 14px',
              borderRadius: 8,
              fontSize: '0.85rem',
              fontWeight: isActive ? 600 : 400,
              textDecoration: 'none',
              transition: 'all 0.15s',
              background: isActive ? 'var(--accent-dim)' : 'transparent',
              color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
              borderLeft: isActive ? '3px solid var(--accent)' : '3px solid transparent',
            })}
          >
            <span style={{ fontSize: '1.1rem', width: 20, textAlign: 'center' }}>{icon}</span>
            {label}
          </NavLink>
        ))}
      </nav>

      {/* User + logout */}
      <div style={{
        padding: '16px',
        borderTop: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <div style={{
            width: 32, height: 32, borderRadius: '50%',
            background: 'linear-gradient(135deg, #7c3aed, #6d28d9)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'white', fontSize: '0.75rem', fontWeight: 700,
          }}>
            {user?.email?.[0]?.toUpperCase() || '?'}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <p style={{
              fontSize: '0.78rem', fontWeight: 500,
              color: 'var(--text-primary)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {user?.email?.split('@')[0] || 'User'}
            </p>
            <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Online</p>
          </div>
        </div>
        <button onClick={logout} className="btn-secondary" style={{ width: '100%', fontSize: '0.75rem', padding: '6px 12px' }}>
          Logout
        </button>
      </div>
    </aside>
  )
}
