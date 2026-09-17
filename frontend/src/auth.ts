const AUTH_KEY = 'nsai-authenticated'
const USER_KEY = 'nsai-user'
const ROLE_KEY = 'nsai-role'
const SESSION_KEY = 'nsai-session'
const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api'

export async function login(username: string, password: string): Promise<boolean> {
  try {
    const response = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (!response.ok) return false
    const session = await response.json()
    window.localStorage.setItem(AUTH_KEY, 'true')
    window.localStorage.setItem(USER_KEY, username)
    window.localStorage.setItem(ROLE_KEY, session.role ?? 'viewer')
    window.localStorage.setItem(SESSION_KEY, session.access_token)
    return true
  } catch {
    return false
  }
}

export function logout() {
  window.localStorage.removeItem(AUTH_KEY)
  window.localStorage.removeItem(USER_KEY)
  window.localStorage.removeItem(ROLE_KEY)
  window.localStorage.removeItem(SESSION_KEY)
}

export function isAuthenticated(): boolean {
  if (typeof window === 'undefined') return false
  return window.localStorage.getItem(AUTH_KEY) === 'true'
}

export function getCurrentUser(): string | null {
  if (typeof window === 'undefined') return null
  return window.localStorage.getItem(USER_KEY)
}

export function getSessionToken(): string | null {
  if (typeof window === 'undefined') return null
  return window.localStorage.getItem(SESSION_KEY)
}

export function getCurrentRole(): string | null {
  if (typeof window === 'undefined') return null
  return window.localStorage.getItem(ROLE_KEY)
}