/**
 * context/AuthContext.jsx — Gestión de autenticación con Supabase.
 *
 * Centralizo toda la lógica de auth en un Context para que cualquier
 * componente pueda acceder al usuario, token, y funciones login/register/logout.
 */

import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { createClient } from '@supabase/supabase-js'

// Leo las credenciales de Supabase desde las variables VITE_*
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || ''
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || ''

// Creo el cliente solo si tengo las credenciales
let supabase = null
if (supabaseUrl && supabaseAnonKey) {
  supabase = createClient(supabaseUrl, supabaseAnonKey)
} else {
  console.error('[AuthContext] VITE_SUPABASE_URL o VITE_SUPABASE_ANON_KEY no configurados')
}

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!supabase) {
      setLoading(false)
      return
    }

    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session) {
        setUser(session.user)
        setToken(session.access_token)
      }
      setLoading(false)
    }).catch(() => setLoading(false))

    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (_event, session) => {
        if (session) {
          setUser(session.user)
          setToken(session.access_token)
        } else {
          setUser(null)
          setToken(null)
        }
      }
    )

    return () => subscription.unsubscribe()
  }, [])

  const login = useCallback(async (email, password) => {
    if (!supabase) return { ok: false, error: 'Supabase not configured' }
    try {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password })
      if (error) return { ok: false, error: error.message }
      return { ok: true, user: data.user }
    } catch (err) {
      return { ok: false, error: err.message }
    }
  }, [])

  const register = useCallback(async (email, password) => {
    if (!supabase) return { ok: false, error: 'Supabase not configured' }
    try {
      const { data, error } = await supabase.auth.signUp({ email, password })
      if (error) return { ok: false, error: error.message }
      return { ok: true, user: data.user }
    } catch (err) {
      return { ok: false, error: err.message }
    }
  }, [])

  const logout = useCallback(async () => {
    if (supabase) await supabase.auth.signOut()
    setUser(null)
    setToken(null)
  }, [])

  const value = {
    user, token, loading,
    login, register, logout,
    isAuthenticated: !!user,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth debe usarse dentro de un AuthProvider')
  }
  return context
}

export default AuthContext
