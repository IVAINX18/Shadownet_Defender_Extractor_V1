/**
 * components/Layout.jsx — Shell principal con topbar + sidebar + contenido.
 *
 * Diseño basado en la referencia:
 * - Sidebar a la izquierda
 * - Topbar con título, status badge, y usuario
 * - Contenido principal scrollable
 */
import { Outlet } from 'react-router-dom'
import { Bell, Search, User } from 'lucide-react'
import Sidebar from './Sidebar'
import { useAuth } from '../context/AuthContext'

export default function Layout() {
  const { user } = useAuth()

  return (
    <div style={{ display: 'flex', width: '100%', minHeight: '100vh', background: 'var(--bg-primary)' }}>
      <Sidebar />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Top bar */}
        <header style={{
          height: 64,
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 32px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            <h2 style={{ fontSize: '0.95rem', fontWeight: 500, color: 'var(--text-primary)' }}>
              ShadowNet Defender <span style={{ color: 'var(--text-muted)', margin: '0 8px' }}>/</span> Overview
            </h2>
            <span className="badge-secure">
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)', display: 'inline-block' }} />
              SECURE / NO THREAT DETECTED
            </span>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
            <div style={{ display: 'flex', gap: 16 }}>
              <button style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}>
                <Search size={18} />
              </button>
              <button style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', display: 'flex', alignItems: 'center', position: 'relative' }}>
                <Bell size={18} />
                <span style={{ position: 'absolute', top: -2, right: -2, width: 8, height: 8, background: 'var(--accent)', borderRadius: '50%', border: '2px solid var(--bg-secondary)' }} />
              </button>
            </div>
            
            <div style={{ width: 1, height: 24, background: 'var(--border)' }} />
            
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ textAlign: 'right' }}>
                <p style={{ fontSize: '0.8rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                  {user?.email?.split('@')[0] || 'User'}
                </p>
                <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                  System Administrator
                </p>
              </div>
              <div style={{
                width: 36, height: 36, borderRadius: '50%',
                background: 'var(--bg-input)', border: '1px solid var(--border)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'var(--text-secondary)'
              }}>
                <User size={18} />
              </div>
            </div>
          </div>
        </header>

        {/* Content */}
        <main style={{ flex: 1, padding: 32, overflowY: 'auto', overflowX: 'hidden' }}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
