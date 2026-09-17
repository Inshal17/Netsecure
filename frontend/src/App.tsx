import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import {
  Activity,
  AlertTriangle,
  Copy,
  ArrowRight,
  Bell,
  ChevronRight,
  Command,
  HardDrive,
  Menu,
  Moon,
  Network,
  Search,
  ShieldCheck,
  Sun,
  UploadCloud,
  UserCircle,
  X,
  type LucideIcon,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  Navigate,
  NavLink,
  Outlet,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useOutletContext,
  useParams,
} from 'react-router-dom'

import LandingPage from './Landingpage'
import LoginPage from './Loginpage'
import RegisterPage from './Registerpage'
import { getCurrentRole, isAuthenticated, logout } from './auth'

import {
  getAnalysisJobs,
  getAnalysisResult,
  getAuditLogs,
  getFrameworks,
  getLiveDashboard,
  getLiveDevices,
  getLiveFindings,
  getLiveAnalyses,
  getLiveReports,
  getUploadedFiles,
  getRemediations,
  getTrainingItems,
  suggestTrainingMapping,
  saveTrainingMapping,
  applyTrainingMappings,
  startAnalysis,
  getStorageInfo,
  reRunUploadedAnalysis,
  downloadReport,
} from './services/api'

// vendorOptions removed; use live devices to derive vendor list
import type { Device, Finding, FrameworkDefinition, ReportItem, TrainingItem } from './types'

type Toast = {
  id: number
  message: string
  variant: 'success' | 'warning' | 'info'
}

type LayoutContext = {
  showToast: (message: string, variant?: 'success' | 'warning' | 'info') => void
  searchTerm: string
  setSearchTerm: (term: string) => void
}

function StatusBadge({ status }: { status: string }) {
  const palette: Record<string, string> = {
    Compliant: 'success',
    'Non-Compliant': 'danger',
    Warning: 'warning',
    Critical: 'danger',
    High: 'danger',
    Medium: 'warning',
    Low: 'info',
    Completed: 'success',
    Processing: 'info',
    Queued: 'neutral',
    Failed: 'danger',
    Open: 'warning',
    Resolved: 'success',
    Investigating: 'info',
    Monitoring: 'neutral',
    Pending: 'neutral',
    'In Progress': 'info',
    Active: 'success',
    Healthy: 'success',
    'Needs Review': 'warning',
    Draft: 'neutral',
    Ready: 'success',
    Archived: 'neutral',
    Success: 'success',
    Failure: 'danger',
  }

  return <span className={`status-badge ${palette[status] ?? 'neutral'}`}>{status}</span>
}

function SeverityPill({ severity }: { severity: string }) {
  const palette: Record<string, string> = {
    Critical: 'critical',
    High: 'high',
    Medium: 'medium',
    Low: 'low',
  }

  return <span className={`severity-pill ${palette[severity] ?? 'low'}`}>{severity}</span>
}

/** Eases a numeric value from 0 to `target` on mount/update. Presentational only. */
function useAnimatedValue(target: number, duration = 900) {
  const [value, setValue] = useState(0)
  const targetRef = useRef(target)

  useEffect(() => {
    targetRef.current = target
    const prefersReduced = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (prefersReduced) {
      setValue(target)
      return
    }
    let raf = 0
    const start = performance.now()
    const animate = (now: number) => {
      const elapsed = now - start
      const progress = Math.min(1, elapsed / duration)
      const eased = 1 - Math.pow(1 - progress, 3)
      setValue(targetRef.current * eased)
      if (progress < 1) raf = requestAnimationFrame(animate)
    }
    raf = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])

  return value
}

/** Renders a string like "82%" or "1,204" with the numeric portion counting up on mount. */
function AnimatedNumber({ value }: { value: string }) {
  const match = value.match(/^(-?[\d,.]+)(.*)$/)
  const numeric = match ? Number(match[1].replace(/,/g, '')) : NaN
  const suffix = match ? match[2] : ''
  const animated = useAnimatedValue(Number.isFinite(numeric) ? numeric : 0, 900)

  if (!Number.isFinite(numeric)) return <>{value}</>

  const isInteger = Number.isInteger(numeric)
  const display = isInteger ? Math.round(animated).toLocaleString() : animated.toFixed(1)
  return <>{display}{suffix}</>
}

/** Circular compliance gauge; the stroke eases in from 0 to `value` on mount. */
function ProgressRing({ value, size = 96, stroke = 10, color = 'var(--signal)', trackColor = 'rgba(37, 99, 235, 0.12)' }: { value: number; size?: number; stroke?: number; color?: string; trackColor?: string }) {
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const animatedValue = useAnimatedValue(value, 1100)
  const clamped = Math.min(100, Math.max(0, animatedValue))
  const offset = circumference - (clamped / 100) * circumference

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="progress-ring" role="img" aria-label={`${Math.round(value)} percent`}>
      <circle cx={size / 2} cy={size / 2} r={radius} stroke={trackColor} strokeWidth={stroke} fill="none" />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        stroke={color}
        strokeWidth={stroke}
        fill="none"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
    </svg>
  )
}

/** Minimal inline trend line — pure presentation, computed from already-fetched numbers. */
function Sparkline({ points, color = 'var(--signal)' }: { points: number[]; color?: string }) {
  if (!points || points.length < 2) return null
  const width = 72
  const height = 26
  const min = Math.min(...points)
  const max = Math.max(...points)
  const range = max - min || 1
  const step = width / (points.length - 1)
  const coords = points.map((value, index) => {
    const x = index * step
    const y = height - ((value - min) / range) * height
    return `${x.toFixed(1)},${y.toFixed(1)}`
  })
  const areaPath = `M0,${height} L${coords.join(' L')} L${width},${height} Z`
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="sparkline" preserveAspectRatio="none">
      <path d={areaPath} fill={color} opacity={0.14} stroke="none" />
      <polyline points={coords.join(' ')} fill="none" stroke={color} strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function StatCard({ label, value, trend, icon: Icon, accent, spark }: { label: string; value: string; trend?: string; icon: LucideIcon; accent?: 'cyan' | 'purple' | 'green' | 'amber' | 'red'; spark?: number[] }) {
  return (
    <div className={`stat-card accent-${accent ?? 'cyan'}`}>
      <div className="stat-head">
        <div>
          <p>{label}</p>
          <h3><AnimatedNumber value={value} /></h3>
        </div>
        <span className={`stat-icon ${accent ?? 'cyan'}`}><Icon size={18} /></span>
      </div>
      <div className="stat-foot">
        {trend ? <div className="trend">{trend}</div> : <span />}
        {spark && spark.length > 1 ? <Sparkline points={spark} /> : null}
      </div>
    </div>
  )
}

function SectionHeader({ title, actions, icon: Icon }: { title: string; actions?: React.ReactNode; icon?: LucideIcon }) {
  return (
    <div className="section-header">
      <h2>{Icon ? <Icon size={16} className="section-icon" /> : null}<span>{title}</span></h2>
      {actions ? <div className="section-actions">{actions}</div> : null}
    </div>
  )
}

function ProtectedRoute() {
  const location = useLocation()
  if (!isAuthenticated()) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }
  return <Outlet />
}

function RoleRoute({ allowed }: { allowed: string[] }) {
  const role = getCurrentRole() ?? 'viewer'
  const context = useOutletContext<LayoutContext>()
  return allowed.includes(role) ? <Outlet context={context} /> : <Navigate to="/dashboard" replace />
}

function Layout() {
  const [searchTerm, setSearchTerm] = useState('')
  const [toasts, setToasts] = useState<Toast[]>([])
  const [notifications, setNotifications] = useState<Toast[]>([])
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [collapsed, setCollapsed] = useState(true)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [paletteQuery, setPaletteQuery] = useState('')
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    if (typeof window === 'undefined') return 'dark'
    return (window.localStorage.getItem('nsai-theme') as 'dark' | 'light') ?? 'dark'
  })
  const [now, setNow] = useState(() => new Date())
  const navRef = useRef<HTMLElement | null>(null)
  const notificationsRef = useRef<HTMLDivElement | null>(null)
  const location = useLocation()
  const navigate = useNavigate()
  const role = getCurrentRole() ?? 'viewer'

  useEffect(() => {
    setMobileNavOpen(false)
  }, [location.pathname])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    window.localStorage.setItem('nsai-theme', theme)
  }, [theme])

  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000 * 30)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setPaletteOpen((current) => !current)
      }
      if (event.key === 'Escape') {
        setPaletteOpen(false)
        setNotificationsOpen(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notificationsRef.current && !notificationsRef.current.contains(event.target as Node)) {
        setNotificationsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const showToast = (message: string, variant: 'success' | 'warning' | 'info' = 'success') => {
    const id = Date.now() + Math.random()
    const entry = { id, message, variant }
    setToasts((current) => [...current, entry])
    setNotifications((current) => [entry, ...current].slice(0, 8))
    window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id))
    }, 3200)
  }

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const pageTitleMap: Record<string, string> = {
    '/dashboard': 'Network Security Posture',
    '/devices': 'Network Devices',
    '/configuration': 'Configuration Ingestion',
    '/analysis': 'Analysis Pipeline',
    '/compliance': 'Compliance Management',
    '/findings': 'Security Findings',
    '/remediation': 'Remediation Center',
    '/training': 'Parser Training',
    '/frameworks': 'Framework Management',
    '/reports': 'Compliance Reports',
    '/audit-logs': 'Audit Logs',
    '/settings': 'Settings',
  }

  const pageDescriptionMap: Record<string, string> = {
    '/dashboard': 'Monitor configuration compliance across your network infrastructure.',
    '/devices': 'Manage monitored infrastructure and compliance posture.',
    '/configuration': 'Upload network device configurations for automated security analysis.',
    '/analysis': 'Track staged validation across normalization and compliance checks.',
    '/compliance': 'Review framework alignment and control coverage across the estate.',
    '/findings': 'Investigate active security issues and remediation priorities.',
    '/remediation': 'Coordinate vendor-aware corrective actions and evidence validation.',
    '/training': 'Teach NetSecureAI how to interpret previously unknown vendor syntax.',
    '/frameworks': 'Maintain supported control baselines and operational coverage.',
    '/reports': 'View and distribute compliance evidence and operational summaries.',
    '/audit-logs': 'Review operational changes, governance actions, and system events.',
    '/settings': 'Tune governance controls, alerts, and platform behavior.',
  }

  const matchedPath = Object.keys(pageTitleMap).find((path) => path !== '/' && location.pathname.startsWith(`${path}/`))
  const currentTitle = pageTitleMap[location.pathname] ?? (matchedPath ? pageTitleMap[matchedPath] : 'NetSecureAI')
  const currentDescription = pageDescriptionMap[location.pathname] ?? (matchedPath ? pageDescriptionMap[matchedPath] : 'Network security operations overview.')

  const navGroups: { label: string; items: { to: string; label: string; icon: LucideIcon }[] }[] = [
    {
      label: 'Overview',
      items: [{ to: '/dashboard', label: 'Dashboard', icon: Activity }],
    },
    {
      label: 'Operations',
      items: [
        { to: '/devices', label: 'Devices', icon: HardDrive },
        { to: '/configuration', label: 'Configuration', icon: UploadCloud },
        { to: '/analysis', label: 'Analysis', icon: Network },
      ],
    },
    {
      label: 'Security',
      items: [
        { to: '/compliance', label: 'Compliance', icon: ShieldCheck },
        { to: '/findings', label: 'Findings', icon: AlertTriangle },
        { to: '/remediation', label: 'Remediation', icon: ArrowRight },
      ],
    },
    {
      label: 'Administration',
      items: [
        ...(role === 'admin' ? [{ to: '/training', label: 'Training', icon: UserCircle }, { to: '/frameworks', label: 'Frameworks', icon: ShieldCheck }] : []),
        { to: '/reports', label: 'Reports', icon: Activity },
        { to: '/audit-logs', label: 'Audit Logs', icon: Bell },
        ...(role === 'admin' ? [{ to: '/settings', label: 'Settings', icon: X }] : []),
      ],
    },
  ]

  const flatNavItems = navGroups.flatMap((group) => group.items)
  const paletteMatches = paletteQuery.trim()
    ? flatNavItems.filter((item) => item.label.toLowerCase().includes(paletteQuery.trim().toLowerCase()))
    : flatNavItems

  // Slides a highlight pill behind the active nav link — measured against the real DOM node
  // so it glides smoothly between items instead of just swapping a background color.
  const [indicatorStyle, setIndicatorStyle] = useState<{ top: number; height: number; opacity: number }>({ top: 0, height: 0, opacity: 0 })

  useLayoutEffect(() => {
    const container = navRef.current
    if (!container) return
    const activeEl = container.querySelector<HTMLElement>('.nav-item.active')
    if (!activeEl) {
      setIndicatorStyle((current) => ({ ...current, opacity: 0 }))
      return
    }
    const containerRect = container.getBoundingClientRect()
    const activeRect = activeEl.getBoundingClientRect()
    setIndicatorStyle({ top: activeRect.top - containerRect.top, height: activeRect.height, opacity: 1 })
  }, [location.pathname, collapsed, mobileNavOpen])

  const timeLabel = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  const dateLabel = now.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' })

  return (
    <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''}`}>
      <header className="topbar">
        <button type="button" className="icon-button mobile-only" aria-label="Toggle navigation" onClick={() => setMobileNavOpen((current) => !current)}>
          <Menu size={18} />
        </button>

        <div className="brand-wrap">
          <div className="brand-mark"><ShieldCheck size={19} /></div>
          <div className="brand-copy">
            <div className="brand-name">NetSecureAI</div>
            <div className="brand-subtitle">Compliance Engine</div>
          </div>
        </div>
      </header>

      <div className="shell-body">
        {mobileNavOpen ? <div className="nav-scrim" onClick={() => setMobileNavOpen(false)} /> : null}

        <aside className={`sidebar ${mobileNavOpen ? 'nav-open' : ''}`}>
          <button type="button" className="sidebar-collapse-toggle" onClick={() => setCollapsed((current) => !current)} aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}>
            {!collapsed ? <span className="toggle-label">Navigation</span> : null}
            <ChevronRight size={16} className="toggle-chevron" />
          </button>

          <nav className="sidebar-nav" aria-label="Main navigation" ref={navRef}>
            <div className="nav-indicator" style={{ top: indicatorStyle.top, height: indicatorStyle.height, opacity: indicatorStyle.opacity }} />
            {navGroups.map((group) => (
              <div className="nav-group" key={group.label}>
                <p className="nav-group-label">{group.label}</p>
                {group.items.map(({ to, label, icon: Icon }) => (
                  <NavLink key={to} to={to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} end={to === '/dashboard'} title={label}>
                    <Icon size={16} />
                    <span>{label}</span>
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>
        </aside>

        <main className="main-panel">
          <div className="subheader">
            <label className="search-box thin-search" aria-label="Search">
              <Search size={15} />
              <input
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                placeholder="Search"
              />
            </label>

            <div className="subheader-actions">
              <button type="button" className="icon-button kbd-button" aria-label="Open command palette" onClick={() => setPaletteOpen(true)} title="Jump to a page (Ctrl/Cmd K)">
                <Command size={16} />
              </button>

              <div className="clock-chip" title={dateLabel}>
                <span className="clock-time">{timeLabel}</span>
                <span className="clock-date">{dateLabel}</span>
              </div>

              <button type="button" className="icon-button" aria-label="Toggle theme" onClick={() => setTheme((current) => (current === 'dark' ? 'light' : 'dark'))}>
                {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
              </button>

              <div className="notifications-wrap" ref={notificationsRef}>
                <button type="button" className="icon-button" aria-label="Notifications" onClick={() => setNotificationsOpen((current) => !current)}>
                  <Bell size={17} />
                  {notifications.length ? <span className="notif-count">{notifications.length}</span> : null}
                </button>
                {notificationsOpen ? (
                  <div className="notifications-panel">
                    <div className="notifications-head">
                      <span>Activity</span>
                      {notifications.length ? (
                        <button type="button" className="ghost-button small" onClick={() => setNotifications([])}>Clear</button>
                      ) : null}
                    </div>
                    {notifications.length ? (
                      <div className="notifications-list">
                        {notifications.map((item) => (
                          <div key={item.id} className={`notification-row ${item.variant}`}>
                            <span className="dot-status" />
                            <span>{item.message}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="notifications-empty">You're all caught up. Actions you take will show up here.</p>
                    )}
                  </div>
                ) : null}
              </div>

              <div className="status-indicator">
                <span className="status-dot" />
                Operational
              </div>
              <button type="button" className="profile-pill" onClick={handleLogout} title="Sign out">
                <UserCircle size={18} />
                <span>{role}</span>
              </button>
            </div>
          </div>

          <div className="content-area">
            <div className="page-heading">
              <h1>{currentTitle}</h1>
              <p>{currentDescription}</p>
            </div>
            <Outlet context={{ showToast, searchTerm, setSearchTerm }} />
          </div>
        </main>
      </div>

      {paletteOpen ? (
        <div className="modal-backdrop" onClick={() => setPaletteOpen(false)}>
          <div className="command-palette" onClick={(event) => event.stopPropagation()}>
            <div className="command-input">
              <Search size={16} />
              <input
                autoFocus
                value={paletteQuery}
                onChange={(event) => setPaletteQuery(event.target.value)}
                placeholder="Jump to a page..."
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && paletteMatches[0]) {
                    navigate(paletteMatches[0].to)
                    setPaletteOpen(false)
                    setPaletteQuery('')
                  }
                }}
              />
              <span className="kbd-hint">Esc</span>
            </div>
            <div className="command-results">
              {paletteMatches.length ? paletteMatches.map(({ to, label, icon: Icon }) => (
                <button
                  type="button"
                  key={to}
                  className="command-result"
                  onClick={() => { navigate(to); setPaletteOpen(false); setPaletteQuery('') }}
                >
                  <Icon size={15} />
                  <span>{label}</span>
                  <ArrowRight size={14} className="command-arrow" />
                </button>
              )) : <p className="empty-state">No matching pages.</p>}
            </div>
          </div>
        </div>
      ) : null}

      <div className="toast-stack" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast ${toast.variant}`}>
            <span>{toast.message}</span>
            <button type="button" onClick={() => setToasts((current) => current.filter((item) => item.id !== toast.id))} aria-label="Dismiss notification">
              <X size={12} />
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

function DashboardPage() {
  const [dashboard, setDashboard] = useState<any | null>(null)
  const [loadError, setLoadError] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    Promise.all([getLiveDashboard(), getLiveFindings()])
      .then(([live, liveFindings]) => setDashboard({
        snapshot: { totalDevices: live.totalDevices, configurationsAnalyzed: live.configurationsAnalyzed, overallScore: live.overallScore, compliantDevices: live.recentActivity.filter((item) => item.status === 'Compliant').length, nonCompliantDevices: live.recentActivity.filter((item) => item.status !== 'Compliant').length, lastAnalysis: live.recentActivity[0]?.date ?? 'No scans yet', criticalFindings: live.severityBreakdown.find((item) => item.name === 'Critical')?.value ?? 0, highRiskFindings: live.severityBreakdown.find((item) => item.name === 'High')?.value ?? 0 },
        trend: live.recentActivity.map((item) => ({ name: item.device, score: item.score })),
        severityBreakdown: live.severityBreakdown,
        vendorCompliance: live.vendorCompliance,
        frameworkComparison: live.frameworkComparison,
        recentActivity: live.recentActivity.map((item) => ({ ...item, analysis: item.framework })),
        criticalFindings: liveFindings.filter((item) => item.severity === 'Critical' || item.severity === 'High').slice(0, 3),
      }))
      .catch((error) => setLoadError(error.message))
  }, [])

  if (loadError) return <div className="empty-state">{loadError}</div>
  if (!dashboard) return <div className="empty-state">Loading persisted scan data…</div>

  return (
    <div className="page-stack">
      <div className="hero-panel">
        <div className="hero-copy">
          <p className="eyebrow">Live Security Posture</p>
          <h2>Overall compliance is holding at {dashboard.snapshot.overallScore}%</h2>
          <p className="hero-subtitle">
            {dashboard.snapshot.totalDevices} devices scanned · last analysis {dashboard.snapshot.lastAnalysis}
          </p>
          <div className="action-row">
            <button type="button" className="primary-button" onClick={() => navigate('/configuration')}>
              <UploadCloud size={16} />
              Upload Configuration
            </button>
            <button type="button" className="secondary-button" onClick={() => navigate('/analysis')}>
              <Activity size={16} />
              Analyze Configuration
            </button>
            <button type="button" className="ghost-button" onClick={() => navigate('/findings')}>
              <AlertTriangle size={16} />
              View Findings
            </button>
          </div>
        </div>
        <div className="hero-ring">
          <ProgressRing value={dashboard.snapshot.overallScore} size={132} stroke={12} />
          <div className="hero-ring-label">
            <strong><AnimatedNumber value={`${dashboard.snapshot.overallScore}%`} /></strong>
            <span>Compliant</span>
          </div>
        </div>
      </div>

      <div className="stats-grid primary-stats">
        <StatCard label="Devices scanned" value={String(dashboard.snapshot.totalDevices)} trend="Unique devices from persisted scans" icon={HardDrive} accent="purple" />
        <StatCard label="Configurations analyzed" value={String(dashboard.snapshot.configurationsAnalyzed)} trend="Persisted scan history" icon={Network} accent="cyan" />
        <StatCard label="Current compliance" value={`${dashboard.snapshot.overallScore}%`} trend="Latest scan for each device" icon={ShieldCheck} accent="green" spark={dashboard.trend.map((item: any) => item.score)} />
        <StatCard label="Open findings" value={String(dashboard.snapshot.criticalFindings + dashboard.snapshot.highRiskFindings)} trend="Critical and high severity" icon={AlertTriangle} accent="red" />
      </div>

      <div className="dashboard-grid">
        <div className="panel chart-panel">
          <SectionHeader title="Recent Scan Scores" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={dashboard.trend}>
                <defs>
                  <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ff8a3d" stopOpacity={0.32} />
                    <stop offset="100%" stopColor="#ff8a3d" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#2a2d36" strokeDasharray="4 4" />
                <XAxis dataKey="name" stroke="#6b7180" />
                <YAxis domain={[50, 100]} stroke="#6b7180" />
                <Tooltip
                  contentStyle={{ background: 'var(--panel)', border: '1px solid var(--border-strong)', borderRadius: 8, color: 'var(--ink)', fontSize: 12 }}
                                    labelStyle={{ color: 'var(--muted)', marginBottom: 4 }}
                                    itemStyle={{ color: 'var(--ink)' }}
                                    cursor={{ fill: 'var(--panel-alt)' }}
                />
                <Area type="monotone" dataKey="score" stroke="#ff8a3d" fill="url(#scoreFill)" strokeWidth={2.5} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel chart-panel">
          <SectionHeader title="Open Findings" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={dashboard.severityBreakdown}>
                <CartesianGrid stroke="#2a2d36" strokeDasharray="4 4" />
                <XAxis dataKey="name" stroke="#6b7180" />
                <YAxis stroke="#6b7180" />
                <Tooltip
                  contentStyle={{ background: 'var(--panel)', border: '1px solid var(--border-strong)', borderRadius: 8, color: 'var(--ink)', fontSize: 12 }}
                                    labelStyle={{ color: 'var(--muted)', marginBottom: 4 }}
                                    itemStyle={{ color: 'var(--ink)' }}
                                    cursor={{ fill: 'var(--panel-alt)' }}
                />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {dashboard.severityBreakdown.map((entry: any) => (
                    <Cell key={entry.name} fill={entry.name === 'Critical' ? '#eb635a' : entry.name === 'High' ? '#ff8a3d' : entry.name === 'Medium' ? '#f2ae4c' : '#7c8aa8'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel chart-panel">
          <SectionHeader title="Vendor Compliance" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={dashboard.vendorCompliance} layout="vertical" margin={{ left: 10 }}>
                <CartesianGrid stroke="#2a2d36" strokeDasharray="4 4" />
                <XAxis type="number" domain={[0, 100]} stroke="#6b7180" />
                <YAxis dataKey="name" type="category" width={110} stroke="#6b7180" />
                <Tooltip
                  contentStyle={{ background: 'var(--panel)', border: '1px solid var(--border-strong)', borderRadius: 8, color: 'var(--ink)', fontSize: 12 }}
                                    labelStyle={{ color: 'var(--muted)', marginBottom: 4 }}
                                    itemStyle={{ color: 'var(--ink)' }}
                                    cursor={{ fill: 'var(--panel-alt)' }}
                />
                <Bar dataKey="score" radius={[0, 6, 6, 0]} fill="#ff8a3d" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel chart-panel">
          <SectionHeader title="Framework Coverage" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={dashboard.frameworkComparison} dataKey="score" nameKey="name" innerRadius={42} outerRadius={76} paddingAngle={3}>
                  {dashboard.frameworkComparison.map((entry: any, index: number) => (
                    <Cell key={entry.name} fill={['#ff8a3d', '#f2ae4c', '#565b68', '#7c8aa8'][index % 4]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: 'var(--panel)', border: '1px solid var(--border-strong)', borderRadius: 8, color: 'var(--ink)', fontSize: 12 }}
                                    labelStyle={{ color: 'var(--muted)', marginBottom: 4 }}
                                    itemStyle={{ color: 'var(--ink)' }}
                                    cursor={{ fill: 'var(--panel-alt)' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="insight-row">
        <div className="panel compact-panel">
          <div className="insight-label">Risk Distribution</div>
          <div className="risk-list">
            {dashboard.severityBreakdown.map((item: any) => <div key={item.name}><span className={`dot ${item.name === 'Critical' ? 'red' : item.name === 'High' ? 'orange' : item.name === 'Medium' ? 'amber' : 'blue'}`} /> {item.name} <strong>{item.value}</strong></div>)}
          </div>
        </div>

        <div className="panel compact-panel">
          <div className="insight-label">Framework Coverage</div>
          <div className="coverage-stack">
            {dashboard.frameworkComparison.map((item: any) => (
              <div key={item.name} className="coverage-item">
                <div className="coverage-head"><span>{item.name}</span><strong>{item.score}%</strong></div>
                <div className="progress-track"><span style={{ width: `${item.score}%` }} /></div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="two-panel-grid">
        <div className="panel">
          <SectionHeader title="Recent Configuration Analysis" />
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Vendor</th>
                  <th>Configuration</th>
                  <th>Last analyzed</th>
                  <th>Compliance</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                    {dashboard.recentActivity.map((row: any) => (
                      <tr key={`${row.device}-${row.date}`}>
                        <td>{row.device}</td>
                        <td>{row.vendor}</td>
                        <td>{row.analysis}</td>
                        <td>{row.date}</td>
                        <td>{row.score}%</td>
                        <td><StatusBadge status={row.status} /></td>
                      </tr>
                    ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <SectionHeader title="Critical Findings" />
          <div className="findings-stack">
            {dashboard.criticalFindings.map((finding: any) => (
              <button type="button" key={finding.id} className="finding-card" onClick={() => navigate(`/findings/${finding.id}`)}>
                <div className="finding-card-head">
                  <div>
                    <strong>{finding.title}</strong>
                    <small>{finding.device}</small>
                  </div>
                  <SeverityPill severity={finding.severity} />
                </div>
                <div className="finding-meta">
                  <span>{finding.device}</span>
                  <StatusBadge status={finding.status} />
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([])
  const [loadError, setLoadError] = useState('')
  const { searchTerm } = useOutletContext<LayoutContext>()
  const [vendorFilter, setVendorFilter] = useState('All')
  const [typeFilter, setTypeFilter] = useState('All')
  const [riskFilter, setRiskFilter] = useState('All')
  const [statusFilter, setStatusFilter] = useState('All')
  const navigate = useNavigate()

  useEffect(() => { getLiveDevices().then(setDevices).catch((error) => setLoadError(error.message)) }, [])

  const vendors = useMemo(() => Array.from(new Set(devices.map((d) => d.vendor).filter(Boolean))), [devices])

  const filtered = useMemo(() => {
    return devices.filter((device) => {
      const matchesSearch = `${device.name} ${device.vendor} ${device.ipAddress}`.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesVendor = vendorFilter === 'All' || device.vendor === vendorFilter
      const matchesType = typeFilter === 'All' || device.deviceType === typeFilter
      const matchesRisk = riskFilter === 'All' || device.risk === riskFilter
      const matchesStatus = statusFilter === 'All' || device.status === statusFilter
      return matchesSearch && matchesVendor && matchesType && matchesRisk && matchesStatus
    })
  }, [devices, vendorFilter, typeFilter, riskFilter, statusFilter, searchTerm])

  return (
    <div className="page-stack">
      {loadError ? <div className="empty-state">{loadError}</div> : null}
      <div className="panel">
        <div className="toolbar-row">
          <div className="filter-row">
            <select value={vendorFilter} onChange={(event) => setVendorFilter(event.target.value)}>
              <option value="All">All vendors</option>
              {vendors.map((vendor) => (
                <option key={vendor} value={vendor}>{vendor}</option>
              ))}
            </select>
            <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
              <option value="All">All device types</option>
              {[...new Set(devices.map((device) => device.deviceType))].map((deviceType) => (
                <option key={deviceType} value={deviceType}>{deviceType}</option>
              ))}
            </select>
            <select value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
              <option value="All">All risk</option>
              {['Low', 'Moderate', 'High', 'Critical'].map((risk) => (
                <option key={risk} value={risk}>{risk}</option>
              ))}
            </select>
            <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
              <option value="All">All status</option>
              {['Compliant', 'Warning', 'Non-Compliant'].map((status) => (
                <option key={status} value={status}>{status}</option>
              ))}
            </select>
          </div>
          <button type="button" className="primary-button" onClick={() => navigate('/configuration')}>
            Add Device
          </button>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Device Name</th>
                <th>Vendor</th>
                <th>Model</th>
                <th>OS/Firmware</th>
                <th>IP Address</th>
                <th>Device Type</th>
                <th>Compliance Score</th>
                <th>Risk</th>
                <th>Last Scan</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length ? filtered.map((device) => (
                <tr key={device.id} onClick={() => navigate(`/devices/${device.id}`)} className="clickable-row">
                  <td>{device.name}</td>
                  <td>{device.vendor}</td>
                  <td>{device.model}</td>
                  <td>{device.firmware}</td>
                  <td>{device.ipAddress}</td>
                  <td>{device.deviceType}</td>
                  <td>{device.complianceScore}%</td>
                  <td><StatusBadge status={device.risk} /></td>
                  <td>{new Date(device.lastScan).toLocaleDateString()}</td>
                  <td><StatusBadge status={device.status} /></td>
                </tr>
              )) : <tr><td colSpan={10} className="empty-cell">No scanned devices yet. Upload a configuration to create the first device record.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function DeviceDetailsPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [device, setDevice] = useState<Device | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [activeTab, setActiveTab] = useState<'Overview' | 'Configuration' | 'Compliance' | 'Findings' | 'Remediation' | 'Audit History'>('Overview')

  useEffect(() => { getLiveDevices().then((items) => setDevice(items.find((item) => item.id === id) ?? null)).finally(() => setLoaded(true)) }, [id])

  if (!loaded) return <div className="empty-state">Loading scanned device…</div>
  if (!device) {
    return <div className="empty-state">Device not found.</div>
  }

  const tabItems = ['Overview', 'Configuration', 'Compliance', 'Findings', 'Remediation', 'Audit History'] as const

  return (
    <div className="page-stack">
      <div className="device-header panel compact-panel">
        <div>
          <p className="eyebrow">Asset Detail</p>
          <h2>{device.name}</h2>
        </div>
        <button type="button" className="primary-button" onClick={() => navigate('/analysis')}>
          <ArrowRight size={16} />
          Run Compliance Scan
        </button>
      </div>

      <div className="device-summary-grid">
        <div className="panel detail-card">
          <p className="label">Vendor</p>
          <h3>{device.vendor}</h3>
        </div>
        <div className="panel detail-card">
          <p className="label">Model</p>
          <h3>{device.model}</h3>
        </div>
        <div className="panel detail-card">
          <p className="label">Serial Number</p>
          <h3>{device.serialNumber}</h3>
        </div>
        <div className="panel detail-card">
          <p className="label">Firmware</p>
          <h3>{device.firmware}</h3>
        </div>
        <div className="panel detail-card">
          <p className="label">IP Address</p>
          <h3>{device.ipAddress}</h3>
        </div>
        <div className="panel detail-card">
          <p className="label">Compliance Score</p>
          <h3>{device.complianceScore}%</h3>
        </div>
      </div>

      <div className="panel">
        <div className="tabs-row">
          {tabItems.map((tab) => (
            <button key={tab} type="button" className={`tab-button ${activeTab === tab ? 'active' : ''}`} onClick={() => setActiveTab(tab)}>
              {tab}
            </button>
          ))}
        </div>

        {activeTab === 'Overview' && (
          <div className="tab-content">
            <div className="key-value-grid">
              <div><span>Device Type</span><strong>{device.deviceType}</strong></div>
              <div><span>Last Scan</span><strong>{new Date(device.lastScan).toLocaleString()}</strong></div>
              <div><span>Location</span><strong>{device.location}</strong></div>
              <div><span>Risk</span><strong><StatusBadge status={device.risk} /></strong></div>
              <div><span>Status</span><strong><StatusBadge status={device.status} /></strong></div>
            </div>
          </div>
        )}

        {activeTab === 'Configuration' && (
          <div className="tab-content">
            <p>Raw configurations are redacted at ingestion and are not displayed in the dashboard. Open the scan result for verified evidence.</p>
            <button type="button" className="secondary-button" onClick={() => navigate(`/analysis/${device.id}`)}>Open scan evidence</button>
          </div>
        )}

        {activeTab === 'Compliance' && (
          <div className="tab-content">
            <p>Compliance evidence is generated per scan, not from a placeholder device record.</p>
            <button type="button" className="secondary-button" onClick={() => navigate(`/analysis/${device.id}`)}>View current compliance result</button>
          </div>
        )}

        {activeTab === 'Findings' && (
          <div className="tab-content">
            <button type="button" className="secondary-button" onClick={() => navigate('/findings')}>View scan-derived findings</button>
          </div>
        )}

        {activeTab === 'Remediation' && (
          <div className="tab-content">
            <button type="button" className="secondary-button" onClick={() => navigate(`/analysis/${device.id}`)}>View remediation evidence</button>
          </div>
        )}

        {activeTab === 'Audit History' && (
          <div className="tab-content">
            <p>Last persisted scan: {new Date(device.lastScan).toLocaleString()}.</p>
          </div>
        )}
      </div>
    </div>
  )
}

function ConfigurationPage() {
  const navigate = useNavigate()
  const { showToast } = useOutletContext<LayoutContext>()
  const [files, setFiles] = useState<File[]>([])
  const [uploadedFiles, setUploadedFiles] = useState<any[]>([])
  const [rerunTarget, setRerunTarget] = useState<any | null>(null)
  const [rerunInProgress, setRerunInProgress] = useState(false)
  const [storageInfo, setStorageInfo] = useState<{ s3_configured: boolean; s3_bucket?: string } | null>(null)
  const [framework, setFramework] = useState('CIS Benchmarks')
  const [frameworkOptions, setFrameworkOptions] = useState<string[]>(['CIS Benchmarks', 'NIST SP 800-53', 'DISA STIG', 'ISO/IEC 27001'])
  const supportedVendors = ['Cisco', 'Juniper', 'Arista', 'Fortinet', 'SONiC', 'Palo Alto', 'HPE Aruba', 'Extreme', 'MikroTik', 'Huawei', 'Check Point', 'Sophos', 'SonicWall', 'AWS', 'Azure', 'GCP']
  const [vendorOptionsState, setVendorOptions] = useState<string[]>(supportedVendors)
  const [vendor, setVendor] = useState(vendorOptionsState[0] ?? 'Cisco')
  const [analysisDepth, setAnalysisDepth] = useState('Standard')

  const handleFileUpload = (incomingFiles: FileList | File[]) => {
    const nextFiles = Array.from(incomingFiles)
    setFiles(nextFiles)
    showToast(`${nextFiles.length} file(s) loaded for analysis`, 'info')
  }

  const handleStartAnalysis = async () => {
    if (!files.length) {
      showToast('Upload at least one configuration file before starting analysis', 'warning')
      return
    }

    const file = files[0]
    try {
      const { job, result } = await startAnalysis(file, vendor, framework)
      showToast(`Analysis complete for ${file.name}`, 'success')
      navigate(`/analysis/${job.id || result.id}`)
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Analysis could not be completed.', 'warning')
    }
  }

  useEffect(() => {
    getFrameworks().then((items) => setFrameworkOptions(items.map((f: any) => f.name))).catch(() => {})
    // derive vendor options from persisted devices
    getLiveDevices().then((items) => {
      const vendors = Array.from(new Set((items || []).map((d: any) => d.vendor).filter(Boolean)))
      if (vendors.length) {
        setVendorOptions((prev) => Array.from(new Set([...prev, ...vendors])))
      }
    }).catch(() => {})
    // load previously uploaded files and storage info
    getUploadedFiles().then((items) => setUploadedFiles(items)).catch(() => {})
    getStorageInfo().then((info) => setStorageInfo(info)).catch(() => setStorageInfo({ s3_configured: false }))
  }, [])

  return (
    <div className="page-stack">
      <div className="panel upload-panel">
        <label className="upload-zone" onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); handleFileUpload(event.dataTransfer.files) }}>
          <UploadCloud size={28} />
          <h3>Drag and drop configurations</h3>
          <p>Supported: .txt, .cfg, .conf, .log</p>
          <input type="file" multiple accept=".txt,.cfg,.conf,.log" onChange={(event) => { if (event.target.files) handleFileUpload(event.target.files) }} />
          <button type="button" className="secondary-button">Browse Files</button>
        </label>
      </div>

      <div className="panel form-panel">
        <div className="settings-grid">
          <label>
            <span>Select compliance framework</span>
            <select value={framework} onChange={(event) => setFramework(event.target.value)}>
              {frameworkOptions.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Select vendor manually</span>
            <select value={vendor} onChange={(event) => setVendor(event.target.value)}>
              {vendorOptionsState.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Analysis depth</span>
            <select value={analysisDepth} onChange={(event) => setAnalysisDepth(event.target.value)}>
              <option value="Standard">Standard</option>
              <option value="Deep">Deep</option>
              <option value="Threat-Focused">Threat-Focused</option>
            </select>
          </label>
        </div>

        <div className="upload-actions">
          <button type="button" className="primary-button" onClick={handleStartAnalysis}>
            <Activity size={16} />
            Start Analysis
          </button>
        </div>
      </div>

      <div className="panel">
        <SectionHeader title="Uploaded Files" actions={<div style={{ fontSize: 12 }}>{storageInfo?.s3_configured ? `Stored: S3 (${storageInfo.s3_bucket})` : 'Stored: Local'}</div>} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Filename</th>
                <th>Size</th>
                <th>Detected vendor</th>
                <th>Device type</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {uploadedFiles.length ? uploadedFiles.map((file) => (
                <tr key={file.id}>
                  <td>
                    <span className="small-badge" style={{ marginRight: 8 }}>{storageInfo?.s3_configured ? 'S3' : 'Local'}</span>
                    {file.filename}
                  </td>
                  <td>{file.size ?? 'n/a'}</td>
                  <td>{file.detectedVendor}</td>
                  <td>{file.deviceType}</td>
                  <td>
                    <div className="action-inline">
                      <a className="ghost-button small" href={file.uploadUrl} target="_blank" rel="noopener noreferrer">Download</a>
                      <button type="button" className="secondary-button small" onClick={() => setRerunTarget(file)}>Re-run</button>
                    </div>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={5} className="empty-cell">No uploaded files yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
      {rerunTarget ? (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal">
            <h3>Re-run analysis</h3>
            <p>Re-run analysis for <strong>{rerunTarget.filename}</strong>? This will re-process the uploaded configuration.</p>
            <div className="action-row" style={{ justifyContent: 'flex-end' }}>
              <button type="button" className="ghost-button" onClick={() => setRerunTarget(null)} disabled={rerunInProgress}>Cancel</button>
              <button type="button" className="primary-button" onClick={async () => {
                setRerunInProgress(true)
                showToast('Re-running analysis…', 'info')
                try {
                  const { job } = await reRunUploadedAnalysis(rerunTarget.id)
                  showToast('Analysis re-run completed', 'success')
                  navigate(`/analysis/${job.id || job}`)
                } catch (err) {
                  showToast(err instanceof Error ? err.message : 'Re-run failed', 'warning')
                } finally {
                  setRerunInProgress(false)
                  setRerunTarget(null)
                }
              }}>
                {rerunInProgress ? 'Running…' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}

function AnalysisPage() {
  const [jobs, setJobs] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    setLoading(true)
    getAnalysisJobs()
      .then((items) => setJobs(items ?? []))
      .catch(() => setJobs([]))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="empty-state">Loading analysis jobs…</div>

  return (
    <div className="page-stack">
      <div className="panel pipeline-panel">
        <h3>Analysis Pipeline</h3>
        <div className="pipeline">
          {['Configuration Ingestion', 'Vendor Detection', 'Normalization', 'Security Baseline Mapping', 'Compliance Evaluation', 'Risk Assessment', 'Remediation Generation', 'Report Generation'].map((step, index, arr) => (
            <div key={step} className="pipeline-step">
              <span>{step}</span>
              {index < arr.length - 1 ? <ChevronRight size={16} /> : null}
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <SectionHeader title="Analysis Jobs" />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Job ID</th>
                <th>File</th>
                <th>Device</th>
                <th>Vendor</th>
                <th>Framework</th>
                <th>Progress</th>
                <th>Status</th>
                <th>Started</th>
                <th>Completed</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.id} onClick={() => navigate(`/analysis/${job.id}`)} className="clickable-row">
                  <td>{job.id}</td>
                  <td>{job.fileName}</td>
                  <td>{job.device?.name ?? job.device}</td>
                  <td>{job.vendor}</td>
                  <td>{job.framework}</td>
                  <td>
                    <div className="progress-bar">
                      <span style={{ width: `${job.progress ?? 100}%` }} />
                    </div>
                    {job.progress ?? 100}%
                  </td>
                  <td><StatusBadge status={job.status ?? 'Completed'} /></td>
                  <td>{job.started ? new Date(job.started).toLocaleDateString() : '—'}</td>
                  <td>{job.completed ? new Date(job.completed).toLocaleDateString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function AnalysisDetailsPage() {
  const { id } = useParams()
  const [result, setResult] = useState<any | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    // Try direct API fetch first
    getAnalysisResult(id)
      .then((res) => {
        setResult(res)
      })
      .catch(() => {
        // Fallback: search list endpoint
        getLiveAnalyses().then((items) => {
          const analysis = (items || []).find((item: any) => item.id === id)
          if (analysis) setResult(analysis)
        }).catch(() => undefined)
      })
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <div className="empty-state">Loading persisted analysis result…</div>
  if (!result) return <div className="empty-state">Analysis result not found.</div>

  return (
    <div className="page-stack">
      <div className="panel summary-grid-panel">
        <div className="summary-row">
          <div><span>Overall compliance score</span><strong>{result.overallScore}%</strong></div>
          <div><span>Risk level</span><strong>{result.riskLevel}</strong></div>
          <div><span>Controls checked</span><strong>{result.controlsChecked}</strong></div>
          <div><span>Passed</span><strong>{result.passed}</strong></div>
          <div><span>Failed</span><strong>{result.failed}</strong></div>
          <div><span>Warnings</span><strong>{result.warnings}</strong></div>
        </div>
      </div>

      <div className="panel">
        <SectionHeader title="Control Results" />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Control ID</th>
                <th>Framework</th>
                <th>Security Requirement</th>
                <th>Result</th>
                <th>Severity</th>
                <th>Evidence</th>
                <th>Remediation</th>
              </tr>
            </thead>
            <tbody>
              {result.controls.map((control: any) => (
                <tr key={control.id}>
                  <td>{control.id}</td>
                  <td>{control.framework}</td>
                  <td>{control.requirement}</td>
                  <td><StatusBadge status={control.result} /></td>
                  <td><SeverityPill severity={control.severity} /></td>
                  <td>{control.evidence}</td>
                  <td>{control.remediation ?? '-'}</td>
                  <td><StatusBadge status={control.result ?? 'Completed'} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loadError, setLoadError] = useState('')
  const { searchTerm } = useOutletContext<LayoutContext>()
  const [severityFilter, setSeverityFilter] = useState('All')
  const [statusFilter, setStatusFilter] = useState('All')
  const navigate = useNavigate()

  useEffect(() => { getLiveFindings().then(setFindings).catch((error) => setLoadError(error.message)) }, [])

  const filtered = findings.filter((finding) => {
    const matchesSearch = `${finding.title} ${finding.device} ${finding.vendor}`.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesSeverity = severityFilter === 'All' || finding.severity === severityFilter
    const matchesStatus = statusFilter === 'All' || finding.status === statusFilter
    return matchesSearch && matchesSeverity && matchesStatus
  })

  const counts = {
    Critical: findings.filter((finding) => finding.severity === 'Critical').length,
    High: findings.filter((finding) => finding.severity === 'High').length,
    Medium: findings.filter((finding) => finding.severity === 'Medium').length,
    Low: findings.filter((finding) => finding.severity === 'Low').length,
  }

  return (
    <div className="page-stack">
      {loadError ? <div className="empty-state">{loadError}</div> : null}
      <div className="summary-cards">
        {Object.entries(counts).map(([label, value]) => (
          <div key={label} className={`panel simple-card severity-summary-${label.toLowerCase()}`}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>

      <div className="panel">
        <div className="filter-row">
          <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
            <option value="All">All severities</option>
            {['Critical', 'High', 'Medium', 'Low'].map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option value="All">All status</option>
            {['Open', 'Investigating', 'Monitoring', 'Resolved'].map((status) => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Finding ID</th>
                <th>Device</th>
                <th>Control</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Detected</th>
                <th>Remediation</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length ? filtered.map((finding) => (
                <tr key={finding.id} onClick={() => navigate(`/findings/${finding.id}`)} className="clickable-row">
                  <td>{finding.id}</td>
                  <td>{finding.device}</td>
                  <td>{finding.controlId}</td>
                  <td><SeverityPill severity={finding.severity} /></td>
                  <td><StatusBadge status={finding.status} /></td>
                  <td>{new Date(finding.detected).toLocaleDateString()}</td>
                  <td>{finding.action}</td>
                </tr>
              )) : <tr><td colSpan={7} className="empty-cell">No active findings from saved scans.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function FindingDetailsPage() {
  const { id } = useParams()
  const [finding, setFinding] = useState<Finding | null>(null)
  const { showToast } = useOutletContext<LayoutContext>()

  useEffect(() => { getLiveFindings().then((items) => setFinding(items.find((item) => item.id === id) ?? null)).catch(() => setFinding(null)) }, [id])

  if (!finding) {
    return <div className="empty-state">Finding not found.</div>
  }

  return (
    <div className="page-stack">
      <div className="panel detail-panel">
        <div className="finding-detail-header">
          <div>
            <p className="eyebrow">Finding Detail</p>
            <h2>{finding.title}</h2>
          </div>
          <div className="detail-actions">
            <SeverityPill severity={finding.severity} />
            <button type="button" className="secondary-button" onClick={() => showToast('Finding marked as resolved', 'success')}>Mark as Resolved</button>
            <button type="button" className="secondary-button" onClick={() => showToast('Remediation workflow created', 'info')}>Create Remediation</button>
            <button type="button" className="ghost-button" onClick={() => showToast('Finding export queued', 'success')}>Export Finding</button>
          </div>
        </div>

        <div className="detail-grid">
          <div><span>Severity</span><strong>{finding.severity}</strong></div>
          <div><span>Risk score</span><strong>{finding.riskScore}</strong></div>
          <div><span>Affected device</span><strong>{finding.device}</strong></div>
          <div><span>Framework</span><strong>{finding.framework}</strong></div>
          <div><span>Control ID</span><strong>{finding.controlId}</strong></div>
          <div><span>Status</span><strong>{finding.status}</strong></div>
        </div>

        <div className="detail-copy">
          <h3>Description</h3>
          <p>{finding.description}</p>
          <h3>Why it matters</h3>
          <p>{finding.whyItMatters}</p>
          <h3>Evidence</h3>
          <p>{finding.evidence}</p>
          <h3>Current configuration</h3>
          <code>{finding.currentConfig}</code>
          <h3>Recommended configuration</h3>
          <code>{finding.recommendedConfig}</code>
          <h3>Remediation command</h3>
          <code>{finding.remediationCommand}</code>
          <h3>References</h3>
          <ul>{finding.references.map((ref) => <li key={ref}>{ref}</li>)}</ul>
        </div>
      </div>
    </div>
  )
}

function RemediationPage() {
  const [tasks, setTasks] = useState<any[]>([])
  const [selected, setSelected] = useState<any | null>(null)

  useEffect(() => {
    getRemediations().then((res) => { setTasks(res as any[]); setSelected((res as any[])[0] ?? null) }).catch(() => {})
  }, [])

  return (
    <div className="page-stack">
      <div className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Finding</th>
                <th>Device</th>
                <th>Severity</th>
                <th>Remediation type</th>
                <th>Command</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {tasks.map((task: any) => (
                <tr key={task.id} onClick={() => setSelected(task)} className={selected?.id === task.id ? 'selected-row clickable-row' : 'clickable-row'}>
                  <td>{task.finding}</td>
                  <td>{task.device}</td>
                  <td><SeverityPill severity={task.severity} /></td>
                  <td>{task.type}</td>
                  <td className="mono-cell" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <code style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{task.command}</code>
                    <button type="button" className="icon-button small" title="Copy command" onClick={(e) => { e.stopPropagation(); navigator.clipboard?.writeText(task.command); }}>
                      <Copy size={14} />
                    </button>
                  </td>
                  <td><StatusBadge status={task.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel remediation-detail">
        <h3>Remediation Detail</h3>
        <div className="detail-grid">
          <div><span>Finding</span><strong>{selected?.finding ?? '-'}</strong></div>
          <div><span>Device</span><strong>{selected?.device ?? '-'}</strong></div>
          <div><span>Severity</span><strong><SeverityPill severity={selected?.severity ?? 'Low'} /></strong></div>
          <div><span>Status</span><strong>{selected?.status ?? '-'}</strong></div>
        </div>
        <div className="code-block-wrap">
          <p>Vendor remediation example (from selected task):</p>
          <code>{selected?.command ?? 'No remediation command available'}</code>
          <small>Commands are vendor-specific; always validate syntax before applying.</small>
        </div>
      </div>
    </div>
  )
}

function TrainingPage() {
  const [items, setItems] = useState<TrainingItem[]>([])
  const [suggestion, setSuggestion] = useState<string | null>(null)
  const { showToast } = useOutletContext<LayoutContext>()

  useEffect(() => { getTrainingItems().then((res) => setItems(res as TrainingItem[])).catch(() => {}) }, [])
  const [form, setForm] = useState({
    command: 'set management access legacy-protocol enable',
    vendor: 'Unknown Vendor',
    category: 'Management Access',
    parameter: 'telnet_disabled',
    meaning: 'Legacy remote management protocol remains enabled on the device.',
    framework: 'CIS',
    control: 'CIS-NET-01',
    expectedSecureValue: 'disabled',
    observedValue: 'false',
    confidence: '91',
  })

  const handleSave = async () => {
    try {
      const created = await saveTrainingMapping({
        command: form.command,
        vendor: form.vendor,
        mapping: form.parameter,
        framework: form.framework,
        confidence: Number(form.confidence),
        createdBy: 'Admin',
        category: form.category,
        parameter: form.parameter,
        meaning: form.meaning,
        expectedSecureValue: form.expectedSecureValue,
        observedValue: form.observedValue === 'true',
      })
      setItems((current) => [created, ...current])
      showToast('Mapping saved to the persistent training model', 'success')
      try {
        showToast('Applying mapping to existing analyses…', 'info')
        await applyTrainingMappings()
        showToast('Mappings applied to stored analyses', 'success')
      } catch (err) {
        showToast('Saved mapping but could not apply to stored analyses', 'warning')
      }
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Mapping could not be saved.', 'warning')
    }
  }

  const handleSuggest = async () => {
    try {
      const result = await suggestTrainingMapping({ command: form.command, vendor: form.vendor })
      setForm((current) => ({
        ...current,
        parameter: result.field_name,
        meaning: result.meaning,
        confidence: String(result.confidence),
        observedValue: String(result.observed_value),
      }))
      setSuggestion(`${result.status}: ${result.reason}`)
    } catch (error) {
      setSuggestion(null)
      showToast(error instanceof Error ? error.message : 'No mapping suggestion available.', 'warning')
    }
  }

  return (
    <div className="page-stack">
      <div className="panel training-panel">
        <h3>UNKNOWN CONFIGURATION</h3>
        <div className="unknown-box">
          <p>Raw command:</p>
          <input value={form.command} onChange={(event) => setForm((current) => ({ ...current, command: event.target.value }))} aria-label="Raw unknown command" />
          <button type="button" className="secondary-button" onClick={handleSuggest}>Suggest Mapping</button>
          {suggestion ? <small>{suggestion}</small> : null}
        </div>

        <div className="training-form-grid">
          <label>
            <span>Vendor or OS</span>
            <input value={form.vendor} onChange={(event) => setForm((current) => ({ ...current, vendor: event.target.value }))} />
          </label>
          <label>
            <span>Security category</span>
            <input value={form.category} onChange={(event) => setForm((current) => ({ ...current, category: event.target.value }))} />
          </label>
          <label>
            <span>Security Baseline Model field</span>
            <select value={form.parameter} onChange={(event) => setForm((current) => ({ ...current, parameter: event.target.value }))}>
              <option value="telnet_disabled">telnet_disabled</option>
              <option value="http_disabled">http_disabled</option>
              <option value="ssh_version">ssh_version</option>
              <option value="logging_enabled">logging_enabled</option>
              <option value="ntp_configured">ntp_configured</option>
              <option value="aaa_enabled">aaa_enabled</option>
              <option value="snmp_secure">snmp_secure</option>
              <option value="idle_timeout">idle_timeout</option>
            </select>
          </label>
          <label>
            <span>Meaning</span>
            <input value={form.meaning} onChange={(event) => setForm((current) => ({ ...current, meaning: event.target.value }))} />
          </label>
          <label>
            <span>Framework control</span>
            <input value={form.control} onChange={(event) => setForm((current) => ({ ...current, control: event.target.value }))} />
          </label>
          <label>
            <span>Expected secure value</span>
            <input value={form.expectedSecureValue} onChange={(event) => setForm((current) => ({ ...current, expectedSecureValue: event.target.value }))} />
          </label>
          <label>
            <span>Observed value is compliant</span>
            <select value={form.observedValue} onChange={(event) => setForm((current) => ({ ...current, observedValue: event.target.value }))}>
              <option value="false">No — record a finding</option>
              <option value="true">Yes — mark as compliant</option>
            </select>
          </label>
          <label>
            <span>Confidence</span>
            <input value={form.confidence} onChange={(event) => setForm((current) => ({ ...current, confidence: event.target.value }))} />
          </label>
        </div>

        <div className="training-buttons">
          <button type="button" className="primary-button" onClick={handleSave}>Save Mapping</button>
          <button type="button" className="secondary-button" onClick={() => showToast('Training entry rejected', 'warning')}>Reject</button>
          <button type="button" className="ghost-button" onClick={() => showToast('Entry flagged for review', 'info')}>Mark for Review</button>
        </div>
      </div>

      <div className="panel">
        <SectionHeader title="Training History" />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Command</th>
                <th>Vendor</th>
                <th>Mapping</th>
                <th>Framework</th>
                <th>Confidence</th>
                <th>Created by</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td>{item.command}</td>
                  <td>{item.vendor}</td>
                  <td>{item.mapping}</td>
                  <td>{item.framework}</td>
                  <td>{item.confidence}%</td>
                  <td>{item.createdBy}</td>
                  <td>{item.date}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function FrameworksPage() {
  const [frameworks, setFrameworks] = useState<FrameworkDefinition[]>([])

  useEffect(() => { getFrameworks().then((res) => setFrameworks(res as FrameworkDefinition[])).catch(() => {}) }, [])

  return (
    <div className="page-stack">
      <div className="framework-cards">
        {frameworks.map((framework: FrameworkDefinition) => (
          <div key={framework.id} className="panel framework-card">
            <div className="framework-card-top">
              <div>
                <p className="eyebrow">Framework</p>
                <h3>{framework.name}</h3>
              </div>
              <StatusBadge status={framework.status} />
            </div>
            <div className="framework-metrics">
              <div><span>Controls</span><strong>{framework.controls}</strong></div>
              <div><span>Active rules</span><strong>{framework.activeRules}</strong></div>
              <div>
                <span>Last updated</span>
                <strong className="framework-updated-value">
                  <span>{new Date(framework.lastUpdated).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}</span>
                  <span>{new Date(framework.lastUpdated).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                </strong>
              </div>
            </div>
            <p className="framework-scope">{framework.scope}</p>
            <div className="framework-source-row">
              <span>{framework.version}</span>
              <span>{framework.reviewStatus}</span>
              {framework.authorityUrl ? <a href={framework.authorityUrl} target="_blank" rel="noreferrer">Source</a> : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function ReportsPage() {
  const [reports, setReports] = useState<ReportItem[]>([])
  const { showToast } = useOutletContext<LayoutContext>()
  const [selectedReport, setSelectedReport] = useState<ReportItem | null>(null)
  const [reportDetails, setReportDetails] = useState<any | null>(null)

  useEffect(() => {
    getLiveReports().then((items) => { setReports(items); setSelectedReport(items[0] ?? null) }).catch((error) => showToast(error.message, 'warning'))
  }, [showToast])

  useEffect(() => {
    if (!selectedReport) { setReportDetails(null); return }
    // fetch the analysis details for the selected report to render real findings
    getAnalysisResult(selectedReport.id as string).then((d) => setReportDetails(d)).catch(() => setReportDetails(null))
  }, [selectedReport])

  const exportFile = async (type: 'PDF' | 'JSON' | 'CSV') => {
    if (!selectedReport) return
    if (type === 'PDF') {
      try {
        const blob = await downloadReport(selectedReport.id)
        const url = URL.createObjectURL(blob)
        const anchor = document.createElement('a')
        anchor.href = url
        anchor.download = `${selectedReport.device}-compliance-report.pdf`
        anchor.click()
        URL.revokeObjectURL(url)
        showToast('PDF report download started', 'success')
      } catch (error) {
        showToast(error instanceof Error ? error.message : 'PDF report download failed.', 'warning')
      }
      return
    }
    const content = type === 'JSON'
      ? JSON.stringify(reportDetails ?? selectedReport, null, 2)
      : [
        ['Device', 'Vendor', 'Framework', 'Compliance Score', 'Generated Date', 'Status'],
        [selectedReport.device, selectedReport.vendor, selectedReport.framework, `${selectedReport.complianceScore}%`, selectedReport.generatedDate, selectedReport.status],
      ].map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n')

    const blob = new Blob([content], { type: type === 'JSON' ? 'application/json;charset=utf-8' : 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `netsecureai-report.${type.toLowerCase()}`
    anchor.click()
    URL.revokeObjectURL(url)
    showToast(`${type} export generated`, 'success')
  }

  return (
    <div className="page-stack">
      <div className="panel">
        <SectionHeader title="Report Management" />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Report name</th>
                <th>Device</th>
                <th>Vendor</th>
                <th>Framework</th>
                <th>Compliance score</th>
                <th>Generated date</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.length ? reports.map((report) => (
                <tr key={report.id}>
                  <td>{report.name}</td>
                  <td>{report.device}</td>
                  <td>{report.vendor}</td>
                  <td>{report.framework}</td>
                  <td>{report.complianceScore}%</td>
                  <td>{report.generatedDate}</td>
                  <td><StatusBadge status={report.status} /></td>
                  <td>
                    <div className="action-inline">
                      <button type="button" className="ghost-button small" onClick={() => setSelectedReport(report)}>View</button>
                      <button type="button" className="secondary-button small" onClick={() => exportFile('PDF')}>Download PDF</button>
                      <button type="button" className="secondary-button small" onClick={() => exportFile('JSON')}>Export JSON</button>
                      <button type="button" className="ghost-button small" onClick={() => exportFile('CSV')}>Export CSV</button>
                    </div>
                  </td>
                </tr>
              )) : <tr><td colSpan={8} className="empty-cell">No reports available until a configuration is scanned.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {selectedReport ? <div className="panel report-preview">
        <h3>NETSECUREAI SECURITY COMPLIANCE REPORT</h3>
        <div className="report-section">
          <h4>Device Information</h4>
          <p>Device: {reportDetails?.device?.name ?? selectedReport.device}</p>
          <p>Vendor: {reportDetails?.vendor ?? selectedReport.vendor}</p>
          <p>Framework: {reportDetails?.framework ?? selectedReport.framework}</p>
        </div>
        <div className="report-section">
          <h4>Compliance Summary</h4>
          <p>Compliance score: {reportDetails?.overallScore ?? selectedReport.complianceScore}%</p>
          <p>Controls tested: {reportDetails?.controls?.length ?? 'n/a'}</p>
          <p>Passed controls: {reportDetails ? reportDetails.controls.filter((c: any) => c.result === 'Pass').length : 'n/a'}</p>
          <p>Failed controls: {reportDetails ? reportDetails.controls.filter((c: any) => c.result === 'Fail').length : 'n/a'}</p>
        </div>
        <div className="report-section">
          <h4>Detailed Findings</h4>
          <ul>
            {reportDetails?.controls?.filter((c: any) => c.result !== 'Pass').map((c: any) => (
              <li key={c.id}>{c.requirement} — <em>{c.severity}</em></li>
            )) ?? <li>No findings available</li>}
          </ul>
        </div>
      </div> : null}
    </div>
  )
}

function AuditLogsPage() {
  const [logs, setLogs] = useState<any[]>([])
  const [dateFilter, setDateFilter] = useState('All')
  const [userFilter, setUserFilter] = useState('All')
  const [actionFilter, setActionFilter] = useState('All')
  const [resultFilter, setResultFilter] = useState('All')

  useEffect(() => { getAuditLogs().then((res) => setLogs(res as any[])).catch(() => {}) }, [])

  const filtered = logs.filter((log: any) => {
    const matchesDate = dateFilter === 'All' || new Date(log.timestamp).toISOString().slice(0, 10) === dateFilter
    const matchesUser = userFilter === 'All' || log.user === userFilter
    const matchesAction = actionFilter === 'All' || log.action === actionFilter
    const matchesResult = resultFilter === 'All' || log.result === resultFilter
    return matchesDate && matchesUser && matchesAction && matchesResult
  })

  return (
    <div className="page-stack">
      <div className="panel">
        <div className="filter-row">
          <select value={dateFilter} onChange={(event) => setDateFilter(event.target.value)}>
            <option value="All">All dates</option>
            <option value="2026-08-25">2026-08-25</option>
          </select>
          <select value={userFilter} onChange={(event) => setUserFilter(event.target.value)}>
            <option value="All">All users</option>
            {[...new Set(logs.map((log) => log.user))].map((user) => (
              <option key={user} value={user}>{user}</option>
            ))}
          </select>
          <select value={actionFilter} onChange={(event) => setActionFilter(event.target.value)}>
            <option value="All">All actions</option>
            {[...new Set(logs.map((log) => log.action))].map((action) => (
              <option key={action} value={action}>{action}</option>
            ))}
          </select>
          <select value={resultFilter} onChange={(event) => setResultFilter(event.target.value)}>
            <option value="All">All results</option>
            {['Success', 'Warning', 'Failure'].map((result) => (
              <option key={result} value={result}>{result}</option>
            ))}
          </select>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>User</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Device</th>
                <th>Result</th>
                <th>IP Address</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((log) => (
                <tr key={log.id}>
                  <td>{new Date(log.timestamp).toLocaleString()}</td>
                  <td>{log.user}</td>
                  <td>{log.action}</td>
                  <td>{log.resource}</td>
                  <td>{log.device}</td>
                  <td><StatusBadge status={log.result} /></td>
                  <td>{log.ipAddress}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function SettingsPage() {
  return (
    <div className="page-stack">
      <div className="settings-layout">
        <div className="panel settings-column">
          <h3>General</h3>
          <label className="setting-row"><span>Default compliance framework</span><input type="checkbox" defaultChecked /></label>
          <label className="setting-row"><span>Auto-scan uploaded configs</span><input type="checkbox" defaultChecked /></label>
          <label className="setting-row"><span>Require approval for AI mappings</span><input type="checkbox" defaultChecked /></label>
        </div>

        <div className="panel settings-column">
          <h3>Security</h3>
          <label className="setting-row"><span>Privileged session recording</span><input type="checkbox" defaultChecked /></label>
          <label className="setting-row"><span>Multi-factor authentication</span><input type="checkbox" defaultChecked /></label>
          <label className="setting-row"><span>Policy drift alerts</span><input type="checkbox" defaultChecked /></label>
        </div>

        <div className="panel settings-column">
          <h3>Notifications</h3>
          <label className="setting-row"><span>Critical finding alerts</span><input type="checkbox" defaultChecked /></label>
          <label className="setting-row"><span>Weekly compliance summary</span><input type="checkbox" defaultChecked /></label>
          <label className="setting-row"><span>Email digests</span><input type="checkbox" /></label>
        </div>

        <div className="panel settings-column">
          <h3>Appearance</h3>
          <label className="setting-row"><span>Compact density</span><input type="checkbox" /></label>
          <label className="setting-row"><span>Reduced motion</span><input type="checkbox" defaultChecked /></label>
          <label className="setting-row"><span>Dark enterprise theme</span><input type="checkbox" defaultChecked /></label>
        </div>
      </div>
    </div>
  )
}

function CompliancePage() {
  const [dashboard, setDashboard] = useState<any | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getLiveDashboard()
      .then((data) => setDashboard(data))
      .catch((err) => setError(err.message))
  }, [])

  if (error) {
    return (
      <div className="page-stack">
        <div className="panel">
          <h2>Compliance</h2>
          <p className="error-text">{error}</p>
        </div>
      </div>
    )
  }

  if (!dashboard) {
    return (
      <div className="page-stack">
        <div className="panel">
          <h2>Compliance</h2>
          <p>Loading compliance data...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="page-stack">

      <div className="panel">
        <div className="section-heading">
          <div>
            <h2>Compliance Management</h2>
            <p>
              Overview of compliance posture, frameworks and control coverage.
            </p>
          </div>
        </div>
      </div>

      <div className="stats-grid">

        <div className="stat-card">
          <span className="label">Overall Compliance</span>
          <strong>{dashboard.overallScore}%</strong>
          <small>Latest analyzed configuration</small>
        </div>

        <div className="stat-card">
          <span className="label">Configurations Analyzed</span>
          <strong>{dashboard.configurationsAnalyzed}</strong>
          <small>Total security analyses</small>
        </div>

        <div className="stat-card">
          <span className="label">Open Findings</span>
          <strong>{dashboard.openFindings}</strong>
          <small>Issues requiring attention</small>
        </div>

        <div className="stat-card">
          <span className="label">Monitored Devices</span>
          <strong>{dashboard.totalDevices}</strong>
          <small>Devices in the current dataset</small>
        </div>

      </div>

      <div className="two-column-grid">

        <div className="panel">
          <div className="section-heading">
            <div>
              <h3>Framework Compliance</h3>
              <p>Compliance score by security framework.</p>
            </div>
          </div>

          {dashboard.frameworkComparison?.length ? (
            <div className="data-list">
              {dashboard.frameworkComparison.map((framework: any) => (
                <div className="data-row" key={framework.name}>
                  <div>
                    <strong>{framework.name}</strong>
                  </div>

                  <div>
                    <strong>{framework.score}%</strong>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              No framework compliance data available yet.
            </div>
          )}
        </div>

        <div className="panel">
          <div className="section-heading">
            <div>
              <h3>Vendor Compliance</h3>
              <p>Compliance posture by device vendor.</p>
            </div>
          </div>

          {dashboard.vendorCompliance?.length ? (
            <div className="data-list">
              {dashboard.vendorCompliance.map((vendor: any) => (
                <div className="data-row" key={vendor.name}>
                  <div>
                    <strong>{vendor.name}</strong>
                  </div>

                  <div>
                    <strong>{vendor.score}%</strong>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              No vendor compliance data available yet.
            </div>
          )}
        </div>

      </div>

      <div className="panel">
        <div className="section-heading">
          <div>
            <h3>Severity Breakdown</h3>
            <p>Current findings grouped by severity.</p>
          </div>
        </div>

        <div className="severity-grid">

          {dashboard.severityBreakdown?.map((item: any) => (
            <div className="severity-card" key={item.name}>
              <span>{item.name}</span>
              <strong>{item.value}</strong>
            </div>
          ))}

        </div>
      </div>

      <div className="panel">
        <div className="section-heading">
          <div>
            <h3>Recent Compliance Activity</h3>
            <p>Latest configuration analyses.</p>
          </div>
        </div>

        {dashboard.recentActivity?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Vendor</th>
                  <th>Framework</th>
                  <th>Score</th>
                  <th>Status</th>
                  <th>Date</th>
                </tr>
              </thead>

              <tbody>
                {dashboard.recentActivity.map((item: any) => (
                  <tr key={item.id}>
                    <td>{item.device}</td>
                    <td>{item.vendor}</td>
                    <td>{item.framework}</td>
                    <td>{item.score}%</td>
                    <td>{item.status}</td>
                    <td>
                      {new Date(item.date).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            No compliance activity available yet.
          </div>
        )}
      </div>

    </div>
  )
}

function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/devices" element={<DevicesPage />} />
          <Route path="/devices/:id" element={<DeviceDetailsPage />} />
          <Route path="/configuration" element={<ConfigurationPage />} />
          <Route path="/analysis" element={<AnalysisPage />} />
          <Route path="/analysis/:id" element={<AnalysisDetailsPage />} />
          <Route path="/compliance" element={<CompliancePage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/findings/:id" element={<FindingDetailsPage />} />
          <Route path="/remediation" element={<RemediationPage />} />
          <Route element={<RoleRoute allowed={['admin']} />}>
            <Route path="/training" element={<TrainingPage />} />
            <Route path="/frameworks" element={<FrameworksPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/audit-logs" element={<AuditLogsPage />} />
        </Route>
      </Route>
    </Routes>
  )
}

export default App