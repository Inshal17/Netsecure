import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { ShieldCheck, UserPlus } from 'lucide-react'

function RegisterPage() {
  const [submitted, setSubmitted] = useState(false)

  // Placeholder only — there is no registration backend yet.
  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    setSubmitted(true)
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
        <p className="eyebrow">Create Account</p>
        <h2>Request access</h2>
        <p className="auth-subtitle">Self-service registration isn't wired up yet — this form is a preview.</p>

        <form className="auth-form" onSubmit={handleSubmit}>
          <label>
            <span>Full name</span>
            <input placeholder="Jane Doe" autoComplete="name" />
          </label>
          <label>
            <span>Work email</span>
            <input type="email" placeholder="jane@company.com" autoComplete="email" />
          </label>
          <label>
            <span>Organization</span>
            <input placeholder="Company name" autoComplete="organization" />
          </label>
          <label>
            <span>Password</span>
            <input type="password" placeholder="Create a password" autoComplete="new-password" />
          </label>
          <label>
            <span>Confirm password</span>
            <input type="password" placeholder="Confirm password" autoComplete="new-password" />
          </label>

          <button type="submit" className="primary-button auth-submit">
            <UserPlus size={16} />
            Create Account
          </button>
        </form>

        {submitted ? (
          <p className="auth-note">Registration is invite-only right now. Contact your NetSecureAI administrator for access.</p>
        ) : null}

        <p className="auth-footnote">
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  )
}

export default RegisterPage