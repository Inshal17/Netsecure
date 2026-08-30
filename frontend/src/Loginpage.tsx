import { useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { LogIn, ShieldCheck } from 'lucide-react'
import { login } from './auth'

function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const location = useLocation() as { state?: { from?: { pathname?: string } } }

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    const ok = login(username.trim(), password)
    if (ok) {
      const redirectTo = location.state?.from?.pathname ?? '/dashboard'
      navigate(redirectTo, { replace: true })
    } else {
      setError('Incorrect ID or password.')
    }
  }

  return (
    <div className="auth-shell">
      <Link to="/" className="brand-wrap auth-brand">
        <div className="brand-mark"><ShieldCheck size={19} /></div>
        <div className="brand-copy">
          <div className="brand-name">NetSecureAI</div>
          <div className="brand-subtitle">Compliance Engine</div>
        </div>
      </Link>

      <div className="panel auth-card">
        <p className="eyebrow">Sign In</p>
        <h2>Welcome back</h2>
        <p className="auth-subtitle">Access is restricted to authorized administrators.</p>

        <form className="auth-form" onSubmit={handleSubmit}>
          <label>
            <span>User ID</span>
            <input
              value={username}
              onChange={(event) => { setUsername(event.target.value); setError('') }}
              placeholder="Enter your ID"
              autoComplete="username"
              autoFocus
            />
          </label>
          <label>
            <span>Password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => { setPassword(event.target.value); setError('') }}
              placeholder="Enter your password"
              autoComplete="current-password"
            />
          </label>

          {error ? <p className="auth-error">{error}</p> : null}

          <button type="submit" className="primary-button auth-submit">
            <LogIn size={16} />
            Sign In
          </button>
        </form>

        <p className="auth-footnote">
          Don't have an account? <Link to="/register">Request access</Link>
        </p>
      </div>
    </div>
  )
}

export default LoginPage