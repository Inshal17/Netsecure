import { Link } from 'react-router-dom'
import { ShieldCheck, Network, AlertTriangle, ArrowRight, UploadCloud } from 'lucide-react'

function LandingPage() {
  return (
    <div className="landing-shell">
      <header className="landing-topbar">
        <div className="brand-wrap">
          <div className="brand-mark"><ShieldCheck size={19} /></div>
          <div className="brand-copy">
            <div className="brand-name">NetSecureAI</div>
            <div className="brand-subtitle">Compliance Engine</div>
          </div>
        </div>
        <div className="landing-topbar-actions">
          <Link to="/login" className="secondary-button">Sign In</Link>
          <Link to="/register" className="primary-button">Create Account</Link>
        </div>
      </header>

      <main className="landing-main">
        <section className="landing-hero">
          <p className="eyebrow">Network Compliance, Automated</p>
          <h1>Know exactly where your network stands.</h1>
          <p className="landing-lede">
            NetSecureAI reads the device configurations you already have, checks them
            against the frameworks you already answer to, and turns the gaps into a
            prioritized, evidence-backed remediation plan — without a manual audit.
          </p>
          <div className="landing-cta-row">
            <Link to="/register" className="primary-button">
              <ArrowRight size={16} />
              Get Started
            </Link>
            <Link to="/login" className="secondary-button">Sign In</Link>
          </div>
        </section>

        <section className="landing-feature-grid">
          <div className="panel landing-feature-card">
            <span className="landing-feature-icon"><UploadCloud size={18} /></span>
            <h3>Upload any configuration</h3>
            <p>Drop in raw device configs from your existing vendors — no agents, no live network access required.</p>
          </div>
          <div className="panel landing-feature-card">
            <span className="landing-feature-icon"><Network size={18} /></span>
            <h3>Automated baseline mapping</h3>
            <p>Every line is matched against CIS, NIST SP 800-53, DISA STIG, and ISO/IEC 27001 controls automatically.</p>
          </div>
          <div className="panel landing-feature-card">
            <span className="landing-feature-icon"><AlertTriangle size={18} /></span>
            <h3>Findings you can act on</h3>
            <p>Every gap comes with severity, evidence, and a vendor-specific remediation command.</p>
          </div>
          <div className="panel landing-feature-card">
            <span className="landing-feature-icon"><ShieldCheck size={18} /></span>
            <h3>Audit-ready reporting</h3>
            <p>Export PDF, JSON, or CSV compliance reports the moment a review comes around.</p>
          </div>
        </section>

        <section className="landing-strip panel">
          <div>
            <strong>4</strong>
            <span>Frameworks supported</span>
          </div>
          <div>
            <strong>Any</strong>
            <span>Vendor syntax, via training</span>
          </div>
          <div>
            <strong>Live</strong>
            <span>Compliance scoring</span>
          </div>
          <div>
            <strong>Local / S3</strong>
            <span>Configuration storage</span>
          </div>
        </section>
      </main>

      <footer className="landing-footer">
        <span>© {new Date().getFullYear()} NetSecureAI</span>
        <span>Internal compliance tooling</span>
      </footer>
    </div>
  )
}

export default LandingPage