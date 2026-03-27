/**
 * App.jsx — Raíz de la aplicación React.
 *
 * Configuro:
 *   - AuthProvider (estado global de auth)
 *   - React Router (rutas públicas y protegidas)
 *   - Token sync con api.js
 */
import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { setApiToken } from './services/api'
import Layout from './components/Layout'
import LoadingSpinner from './components/LoadingSpinner'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import DashboardPage from './pages/DashboardPage'
import ScanPage from './pages/ScanPage'
import HistoryPage from './pages/HistoryPage'

/**
 * ProtectedRoute — Si no está autenticado, redirige a /login.
 */
function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '100vh',
          width: '100%',
          background: 'var(--bg-primary)',
        }}
      >
        <LoadingSpinner size="lg" text="Verifying session..." />
      </div>
    )
  }

  if (!isAuthenticated) return <Navigate to="/login" replace />
  return children
}

/**
 * HomeRedirect — / y rutas desconocidas: login si no hay sesión, dashboard si sí.
 * Así http://localhost:5173/ no depende de añadir /login a mano.
 */
function HomeRedirect() {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '100vh',
          width: '100%',
          background: 'var(--bg-primary)',
        }}
      >
        <LoadingSpinner size="lg" text="Verifying session..." />
      </div>
    )
  }

  return <Navigate to={isAuthenticated ? '/dashboard' : '/login'} replace />
}

/**
 * TokenSync — Sincronizo el token del AuthContext con la capa API.
 * Cada vez que cambia el token, actualizo el interceptor de Axios.
 */
function TokenSync({ children }) {
  const { token } = useAuth()

  useEffect(() => {
    setApiToken(token)
  }, [token])

  return children
}

function App() {
  return (
    <AuthProvider>
      <TokenSync>
        <BrowserRouter>
          <Routes>
            {/* Public routes */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />

            {/* Protected routes with Layout */}
            <Route
              element={
                <ProtectedRoute>
                  <Layout />
                </ProtectedRoute>
              }
            >
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/scan" element={<ScanPage />} />
              <Route path="/history" element={<HistoryPage />} />
            </Route>

            {/* Raíz y rutas no definidas */}
            <Route path="/" element={<HomeRedirect />} />
            <Route path="*" element={<HomeRedirect />} />
          </Routes>
        </BrowserRouter>
      </TokenSync>
    </AuthProvider>
  )
}

export default App
