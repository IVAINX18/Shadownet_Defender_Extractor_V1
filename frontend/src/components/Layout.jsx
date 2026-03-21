/**
 * components/Layout.jsx — Shell principal con topbar + sidebar + contenido.
 *
 * Diseño basado en la referencia:
 * - Sidebar a la izquierda
 * - Topbar con título, status badge, y usuario
 * - Contenido principal scrollable
 */
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import { useAuth } from '../context/AuthContext'

export default function Layout() {
  const { user } = useAuth()

  return (
    <div style={{ display: 'flex', width: '100%', minHeight: '100vh' }}>
      <Sidebar />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {/* Top bar */}
        <header style={{
          height: 56,
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 24px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <h2 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              ShadowNet Defender - Malware Detection
            </h2>
            <span className="badge-secure">
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)', display: 'inline-block' }} />
              SECURE / NO THREAT DETECTED
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <span style={{ fontSize: '1rem', cursor: 'pointer', color: 'var(--text-secondary)' }}>🔔</span>
            <span style={{ fontSize: '1rem', cursor: 'pointer', color: 'var(--text-secondary)' }}>🔍</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div>
                <p style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', textAlign: 'right' }}>
                  {user?.email?.split('@')[0] || 'User'}
                </p>
                <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textAlign: 'right' }}>
                  System Admin
                </p>
              </div>
              <div style={{
                width: 32, height: 32, borderRadius: '50%',
                background: 'linear-gradient(135deg, #7c3aed, #6d28d9)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'white', fontSize: '0.75rem', fontWeight: 700,
              }}>
                {user?.email?.[0]?.toUpperCase() || '?'}
              </div>
            </div>
          </div>
        </header>

        {/* Content */}
        <main style={{ flex: 1, padding: 24, overflowY: 'auto', background: 'var(--bg-primary)' }}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
