// Minimal hardcoded auth for NetSecureAI.
// Exactly one account can sign in. Change the two constants below to rotate it.
// This is client-side only (no backend check) — fine for a gated internal
// dashboard, not a substitute for real authentication if this ever faces
// the public internet.

const AUTH_KEY = 'nsai-authenticated'
const USER_KEY = 'nsai-user'

const VALID_USERNAME = 'admin'
const VALID_PASSWORD = 'admin@123'

export function login(username: string, password: string): boolean {
  const ok = username === VALID_USERNAME && password === VALID_PASSWORD
  if (ok) {
    window.localStorage.setItem(AUTH_KEY, 'true')
    window.localStorage.setItem(USER_KEY, username)
  }
  return ok
}

export function logout() {
  window.localStorage.removeItem(AUTH_KEY)
  window.localStorage.removeItem(USER_KEY)
}

export function isAuthenticated(): boolean {
  if (typeof window === 'undefined') return false
  return window.localStorage.getItem(AUTH_KEY) === 'true'
}

export function getCurrentUser(): string | null {
  if (typeof window === 'undefined') return null
  return window.localStorage.getItem(USER_KEY)
}