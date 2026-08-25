import { useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bell,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  FileText,
  Gauge,
  HardDrive,
  ListFilter,
  Menu,
  Network,
  Search,
  Settings,
  ShieldCheck,
  ShieldOff,
  Sparkles,
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
  NavLink,
  Outlet,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useOutletContext,
  useParams,
} from 'react-router-dom'
import {
  getAnalysisJobs,
  getAnalysisResult,
  getAuditLogs,
  getDashboardStats,
  getDevice,
  getDevices,
  getFinding,
  getFindings,
  getFrameworks,
  getRemediations,
  getReports,
  getTrainingItems,
  saveTrainingMapping,
  startAnalysis,
} from './services/api'
import { frameworkOptions, vendorOptions } from './services/mockData'
import type { FrameworkDefinition, TrainingItem } from './types'
import './App.css'

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

const navItems = [
  { to: '/', label: 'Dashboard', icon: Gauge },
  { to: '/devices', label: 'Devices', icon: HardDrive },
  { to: '/configuration', label: 'Configuration', icon: UploadCloud },
  { to: '/analysis', label: 'Analysis', icon: Activity },
  { to: '/compliance', label: 'Compliance', icon: ShieldCheck },
  { to: '/findings', label: 'Findings', icon: AlertTriangle },
  { to: '/remediation', label: 'Remediation', icon: WrenchIcon },
  { to: '/training', label: 'AI Training', icon: Sparkles },
  { to: '/frameworks', label: 'Frameworks', icon: Network },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/audit-logs', label: 'Audit Logs', icon: ListFilter },
  { to: '/settings', label: 'Settings', icon: Settings },
]

function WrenchIcon(props: React.ComponentProps<typeof Settings>) {
  return <Settings {...props} />
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

function StatCard({ label, value, trend, icon: Icon, accent }: { label: string; value: string; trend?: string; icon: LucideIcon; accent?: 'cyan' | 'purple' | 'green' | 'amber' | 'red' }) {
  return (
    <div className="stat-card">
      <div className="stat-head">
        <div>
          <p>{label}</p>
          <h3>{value}</h3>
        </div>
        <span className={`stat-icon ${accent ?? 'cyan'}`}><Icon size={18} /></span>
      </div>
      {trend ? <div className="trend">{trend}</div> : null}
    </div>
  )
}

function SectionHeader({ title, actions }: { title: string; actions?: React.ReactNode }) {
  return (
    <div className="section-header">
      <h2>{title}</h2>
      {actions ? <div className="section-actions">{actions}</div> : null}
    </div>
  )
}

function Layout() {
  const [searchTerm, setSearchTerm] = useState('')
  const [toasts, setToasts] = useState<Toast[]>([])
  const location = useLocation()

  const showToast = (message: string, variant: 'success' | 'warning' | 'info' = 'success') => {
    const id = Date.now() + Math.random()
    setToasts((current) => [...current, { id, message, variant }])
    window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id))
    }, 3200)
  }

  const pageTitleMap: Record<string, string> = {
    '/': 'Dashboard',
    '/devices': 'Device Inventory',
    '/configuration': 'Configuration Upload',
    '/analysis': 'Analysis Center',
    '/compliance': 'Compliance Overview',
    '/findings': 'Security Findings',
    '/remediation': 'Remediation Center',
    '/training': 'AI Training Module',
    '/frameworks': 'Framework Management',
    '/reports': 'Reports',
    '/audit-logs': 'Audit Logs',
    '/settings': 'Settings',
  }

  const currentTitle = pageTitleMap[location.pathname] ?? 'NetSecureAI'

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-wrap">
          <div className="brand-mark"><ShieldCheck size={22} /></div>
          <div>
            <div className="brand-name">NetSecureAI</div>
            <div className="brand-subtitle">Compliance Engine</div>
          </div>
        </div>

        <nav className="sidebar-nav" aria-label="Main navigation">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} end={to === '/'}>
              <Icon size={16} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="left-header">
            <button type="button" className="icon-button mobile-only" aria-label="Toggle navigation">
              <Menu size={18} />
            </button>
            <div>
              <p className="eyebrow">Security Operations</p>
              <h1>{currentTitle}</h1>
            </div>
          </div>

          <div className="right-header">
            <label className="search-box" aria-label="Search">
              <Search size={16} />
              <input
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                placeholder="Search assets, findings, controls..."
              />
            </label>
            <button type="button" className="icon-button" aria-label="Notifications">
              <Bell size={17} />
            </button>
            <div className="status-indicator">
              <span className="status-dot" />
              System healthy
            </div>
            <div className="profile-pill">
              <UserCircle size={18} />
              <span>Admin</span>
            </div>
          </div>
        </header>

        <div className="content-area">
          <Outlet context={{ showToast, searchTerm, setSearchTerm }} />
        </div>
      </main>

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
  const dashboard = getDashboardStats()
  const navigate = useNavigate()

  return (
    <div className="page-stack">
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

      <div className="stats-grid">
        <StatCard label="Overall Security Compliance Score" value={`${dashboard.snapshot.overallScore}%`} trend="+4.2% vs last cycle" icon={ShieldCheck} accent="cyan" />
        <StatCard label="Total Devices" value={String(dashboard.snapshot.totalDevices)} trend="Across all vendors" icon={HardDrive} accent="purple" />
        <StatCard label="Compliant Devices" value={String(dashboard.snapshot.compliantDevices)} trend="Healthy baseline" icon={CheckCircle2} accent="green" />
        <StatCard label="Non-Compliant Devices" value={String(dashboard.snapshot.nonCompliantDevices)} trend="Requires remediation" icon={ShieldOff} accent="red" />
        <StatCard label="Critical Findings" value={String(dashboard.snapshot.criticalFindings)} trend="Priority action" icon={AlertTriangle} accent="red" />
        <StatCard label="High Risk Findings" value={String(dashboard.snapshot.highRiskFindings)} trend="Escalated" icon={AlertTriangle} accent="amber" />
        <StatCard label="Configurations Analyzed" value={String(dashboard.snapshot.configurationsAnalyzed)} trend="This reporting period" icon={Network} accent="cyan" />
        <StatCard label="Last Analysis" value={new Date(dashboard.snapshot.lastAnalysis).toLocaleString()} trend="Autonomous scan" icon={CircleDashed} accent="purple" />
      </div>

      <div className="dashboard-grid">
        <div className="panel chart-panel">
          <SectionHeader title="Compliance Score Trend" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={dashboard.trend}>
                <defs>
                  <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#67e8f9" stopOpacity={0.45} />
                    <stop offset="100%" stopColor="#67e8f9" stopOpacity={0.04} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#203047" strokeDasharray="4 4" />
                <XAxis dataKey="name" stroke="#8aa4be" />
                <YAxis domain={[50, 100]} stroke="#8aa4be" />
                <Tooltip />
                <Area type="monotone" dataKey="score" stroke="#5eead4" fill="url(#scoreFill)" strokeWidth={3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel chart-panel">
          <SectionHeader title="Findings by Severity" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={dashboard.severityBreakdown}>
                <CartesianGrid stroke="#203047" strokeDasharray="4 4" />
                <XAxis dataKey="name" stroke="#8aa4be" />
                <YAxis stroke="#8aa4be" />
                <Tooltip />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {dashboard.severityBreakdown.map((entry) => (
                    <Cell key={entry.name} fill={entry.name === 'Critical' ? '#ef4444' : entry.name === 'High' ? '#f59e0b' : entry.name === 'Medium' ? '#a78bfa' : '#38bdf8'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel chart-panel">
          <SectionHeader title="Compliance by Vendor" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={dashboard.vendorCompliance} layout="vertical" margin={{ left: 10 }}>
                <CartesianGrid stroke="#203047" strokeDasharray="4 4" />
                <XAxis type="number" domain={[0, 100]} stroke="#8aa4be" />
                <YAxis dataKey="name" type="category" width={110} stroke="#8aa4be" />
                <Tooltip />
                <Bar dataKey="score" radius={[0, 6, 6, 0]} fill="#7dd3fc" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel chart-panel">
          <SectionHeader title="Framework Compliance Comparison" />
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={dashboard.frameworkComparison} dataKey="score" nameKey="name" innerRadius={44} outerRadius={82} paddingAngle={3}>
                  {dashboard.frameworkComparison.map((entry, index) => (
                    <Cell key={entry.name} fill={['#67e8f9', '#a78bfa', '#fbbf24', '#34d399'][index % 4]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="two-panel-grid">
        <div className="panel">
          <SectionHeader title="Recent Activity" />
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Vendor</th>
                  <th>Analysis</th>
                  <th>Framework</th>
                  <th>Score</th>
                  <th>Status</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {dashboard.recentActivity.map((row) => (
                  <tr key={`${row.device}-${row.date}`}>
                    <td>{row.device}</td>
                    <td>{row.vendor}</td>
                    <td>{row.analysis}</td>
                    <td>{row.framework}</td>
                    <td>{row.score}%</td>
                    <td><StatusBadge status={row.status} /></td>
                    <td>{row.date}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <SectionHeader title="Critical Findings" />
          <div className="findings-stack">
            {dashboard.criticalFindings.map((finding) => (
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
  const devices = getDevices()
  const { searchTerm } = useOutletContext<LayoutContext>()
  const [vendorFilter, setVendorFilter] = useState('All')
  const [typeFilter, setTypeFilter] = useState('All')
  const [riskFilter, setRiskFilter] = useState('All')
  const [statusFilter, setStatusFilter] = useState('All')
  const navigate = useNavigate()

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
      <div className="panel">
        <div className="filter-row">
          <select value={vendorFilter} onChange={(event) => setVendorFilter(event.target.value)}>
            <option value="All">All vendors</option>
            {vendorOptions.map((vendor) => (
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
              {filtered.map((device) => (
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
              ))}
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
  const device = getDevice(id ?? '')
  const [activeTab, setActiveTab] = useState<'Overview' | 'Configuration' | 'Compliance' | 'Findings' | 'Remediation' | 'Audit History'>('Overview')

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
            <pre className="code-block">hostname {device.name}
service tcp-keepalives-in
logging host 10.10.50.20
ip access-list extended mgmt-acl
 permit tcp any host {device.ipAddress} eq 22
 deny ip any any
!</pre>
          </div>
        )}

        {activeTab === 'Compliance' && (
          <div className="tab-content">
            <table>
              <thead>
                <tr>
                  <th>Control ID</th>
                  <th>Description</th>
                  <th>Status</th>
                  <th>Severity</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>CIS-NET-01</td>
                  <td>Disable legacy management protocols</td>
                  <td><StatusBadge status="Non-Compliant" /></td>
                  <td><SeverityPill severity="Critical" /></td>
                  <td>telnet enabled</td>
                </tr>
                <tr>
                  <td>CIS-NET-02</td>
                  <td>Configure secure shell management</td>
                  <td><StatusBadge status="Compliant" /></td>
                  <td><SeverityPill severity="High" /></td>
                  <td>SSH version 2 configured</td>
                </tr>
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'Findings' && (
          <div className="tab-content">
            <p>1 active finding: Telnet enabled on management interface.</p>
          </div>
        )}

        {activeTab === 'Remediation' && (
          <div className="tab-content">
            <p>Recommended action: enforce SSH and remove Telnet service from management plane.</p>
          </div>
        )}

        {activeTab === 'Audit History' && (
          <div className="tab-content">
            <p>Last audit: 2026-08-25 08:12 UTC by A. Patel.</p>
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
  const [framework, setFramework] = useState('CIS Benchmarks')
  const [vendor, setVendor] = useState('Cisco')
  const [analysisDepth, setAnalysisDepth] = useState('Standard')

  const handleFileUpload = (incomingFiles: FileList | File[]) => {
    const nextFiles = Array.from(incomingFiles)
    setFiles(nextFiles)
    showToast(`${nextFiles.length} file(s) loaded for analysis`, 'info')
  }

  const handleStartAnalysis = () => {
    if (!files.length) {
      showToast('Upload at least one configuration file before starting analysis', 'warning')
      return
    }

    const file = files[0]
    const { job, result } = startAnalysis(file.name, vendor, framework)
    showToast(`Analysis started for ${file.name}`, 'success')
    navigate(`/analysis/${job.id || result.id}`)
  }

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
              {vendorOptions.map((option) => (
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
        <SectionHeader title="Uploaded Files" />
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
              {files.length ? files.map((file) => (
                <tr key={file.name}>
                  <td>{file.name}</td>
                  <td>{(file.size / 1024).toFixed(0)} KB</td>
                  <td>{vendor}</td>
                  <td>Router</td>
                  <td><StatusBadge status="Detected" /></td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={5} className="empty-cell">No files uploaded yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function AnalysisPage() {
  const jobs = getAnalysisJobs()
  const navigate = useNavigate()

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
                  <td>{job.device}</td>
                  <td>{job.vendor}</td>
                  <td>{job.framework}</td>
                  <td>
                    <div className="progress-bar">
                      <span style={{ width: `${job.progress}%` }} />
                    </div>
                    {job.progress}%
                  </td>
                  <td><StatusBadge status={job.status} /></td>
                  <td>{new Date(job.started).toLocaleDateString()}</td>
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
  const result = getAnalysisResult(id ?? '')
  if (!result) {
    return <div className="empty-state">Analysis result not found.</div>
  }

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
              {result.controls.map((control) => (
                <tr key={control.id}>
                  <td>{control.id}</td>
                  <td>{control.framework}</td>
                  <td>{control.requirement}</td>
                  <td><StatusBadge status={control.result} /></td>
                  <td><SeverityPill severity={control.severity} /></td>
                  <td>{control.evidence}</td>
                  <td>{control.remediation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function CompliancePage() {
  const panelData = [
    { label: 'Overall compliance', value: '81%', detail: 'Across 6 production devices' },
    { label: 'Controls validated', value: '1,432', detail: 'Monthly evaluation cycle' },
    { label: 'Policy drift', value: '12%', detail: 'Detected from baseline' },
  ]

  return (
    <div className="page-stack">
      <div className="stats-grid triple">
        {panelData.map((item) => (
          <div key={item.label} className="panel stat-box">
            <p>{item.label}</p>
            <h3>{item.value}</h3>
            <small>{item.detail}</small>
          </div>
        ))}
      </div>

      <div className="panel">
        <SectionHeader title="Framework Alignment" />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Framework</th>
                <th>Controls</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>Coverage</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {[
                { name: 'CIS Benchmarks', controls: 128, passed: 111, failed: 17, coverage: '92%', status: 'Compliant' },
                { name: 'NIST SP 800-53', controls: 254, passed: 192, failed: 62, coverage: '76%', status: 'Warning' },
                { name: 'DISA STIG', controls: 315, passed: 208, failed: 107, coverage: '66%', status: 'Non-Compliant' },
                { name: 'ISO/IEC 27001', controls: 159, passed: 121, failed: 38, coverage: '76%', status: 'Warning' },
              ].map((row) => (
                <tr key={row.name}>
                  <td>{row.name}</td>
                  <td>{row.controls}</td>
                  <td>{row.passed}</td>
                  <td>{row.failed}</td>
                  <td>{row.coverage}</td>
                  <td><StatusBadge status={row.status} /></td>
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
  const findings = getFindings()
  const { searchTerm } = useOutletContext<LayoutContext>()
  const [severityFilter, setSeverityFilter] = useState('All')
  const [statusFilter, setStatusFilter] = useState('All')
  const navigate = useNavigate()

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
      <div className="summary-cards">
        {Object.entries(counts).map(([label, value]) => (
          <div key={label} className="panel simple-card">
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
                <th>Finding</th>
                <th>Device</th>
                <th>Vendor</th>
                <th>Framework</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Status</th>
                <th>Detected</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((finding) => (
                <tr key={finding.id} onClick={() => navigate(`/findings/${finding.id}`)} className="clickable-row">
                  <td>{finding.title}</td>
                  <td>{finding.device}</td>
                  <td>{finding.vendor}</td>
                  <td>{finding.framework}</td>
                  <td><SeverityPill severity={finding.severity} /></td>
                  <td>{finding.category}</td>
                  <td><StatusBadge status={finding.status} /></td>
                  <td>{new Date(finding.detected).toLocaleDateString()}</td>
                  <td>{finding.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function FindingDetailsPage() {
  const { id } = useParams()
  const finding = getFinding(id ?? '')
  const { showToast } = useOutletContext<LayoutContext>()

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
  const tasks = getRemediations()
  const [selected, setSelected] = useState(tasks[0])

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
              {tasks.map((task) => (
                <tr key={task.id} onClick={() => setSelected(task)} className={selected.id === task.id ? 'selected-row clickable-row' : 'clickable-row'}>
                  <td>{task.finding}</td>
                  <td>{task.device}</td>
                  <td><SeverityPill severity={task.severity} /></td>
                  <td>{task.type}</td>
                  <td className="mono-cell">{task.command}</td>
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
          <div><span>Finding</span><strong>{selected.finding}</strong></div>
          <div><span>Device</span><strong>{selected.device}</strong></div>
          <div><span>Severity</span><strong><SeverityPill severity={selected.severity} /></strong></div>
          <div><span>Status</span><strong>{selected.status}</strong></div>
        </div>
        <div className="code-block-wrap">
          <p>Cisco remediation example (mock only):</p>
          <code>{selected.command}</code>
          <p>Fortinet example (mock only):</p>
          <code>config system global
set admin-sport 443
end</code>
          <small>These are demonstration commands only and will be validated by a backend vendor-specific parser in production.</small>
        </div>
      </div>
    </div>
  )
}

function TrainingPage() {
  const initialTraining = getTrainingItems()
  const [items, setItems] = useState<TrainingItem[]>(initialTraining)
  const { showToast } = useOutletContext<LayoutContext>()
  const [form, setForm] = useState({
    category: 'Management Access',
    parameter: 'insecure_protocol',
    meaning: 'Legacy remote management protocol remains enabled on the device.',
    framework: 'CIS',
    control: 'CIS-NET-01',
    expectedSecureValue: 'disabled',
    confidence: '91',
  })

  const handleSave = () => {
    const created = saveTrainingMapping({
      command: 'set management access legacy-protocol enable',
      vendor: 'Unknown Vendor',
      mapping: 'legacy_protocol_disabled',
      framework: form.framework,
      confidence: Number(form.confidence),
      createdBy: 'A. Patel',
      category: form.category,
      parameter: form.parameter,
      meaning: form.meaning,
      expectedSecureValue: form.expectedSecureValue,
    })
    setItems((current) => [created, ...current])
    showToast('Mapping saved to training model', 'success')
  }

  return (
    <div className="page-stack">
      <div className="panel training-panel">
        <h3>UNKNOWN CONFIGURATION</h3>
        <div className="unknown-box">
          <p>Raw command:</p>
          <code>set management access legacy-protocol enable</code>
        </div>

        <div className="training-form-grid">
          <label>
            <span>Security category</span>
            <input value={form.category} onChange={(event) => setForm((current) => ({ ...current, category: event.target.value }))} />
          </label>
          <label>
            <span>Security parameter</span>
            <input value={form.parameter} onChange={(event) => setForm((current) => ({ ...current, parameter: event.target.value }))} />
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
  const frameworks: FrameworkDefinition[] = getFrameworks()

  return (
    <div className="page-stack">
      <div className="framework-cards">
        {frameworks.map((framework) => (
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
              <div><span>Last updated</span><strong>{framework.lastUpdated}</strong></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function ReportsPage() {
  const reports = getReports()
  const { showToast } = useOutletContext<LayoutContext>()
  const [selectedReport, setSelectedReport] = useState(reports[0])

  const exportFile = (type: 'PDF' | 'JSON' | 'CSV') => {
    const content = type === 'PDF'
      ? 'NETSECUREAI SECURITY COMPLIANCE REPORT\n\nDevice Information\nCompliance Summary\nFramework\nControls Tested\nPassed Controls\nFailed Controls\nRisk Summary\nDetailed Findings\nEvidence\nRemediation Recommendations\nAudit Information'
      : JSON.stringify(selectedReport, null, 2)

    const blob = new Blob([content], { type: type === 'PDF' ? 'text/plain;charset=utf-8' : 'application/json;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `netsecureai-report.${type === 'PDF' ? 'txt' : type.toLowerCase()}`
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
              {reports.map((report) => (
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
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel report-preview">
        <h3>NETSECUREAI SECURITY COMPLIANCE REPORT</h3>
        <div className="report-section">
          <h4>Device Information</h4>
          <p>Device: {selectedReport.device}</p>
          <p>Vendor: {selectedReport.vendor}</p>
          <p>Framework: {selectedReport.framework}</p>
        </div>
        <div className="report-section">
          <h4>Compliance Summary</h4>
          <p>Compliance score: {selectedReport.complianceScore}%</p>
          <p>Controls tested: 128</p>
          <p>Passed controls: 111</p>
          <p>Failed controls: 17</p>
        </div>
        <div className="report-section">
          <h4>Detailed Findings</h4>
          <ul>
            <li>Telnet enabled on management interface</li>
            <li>HTTP management interface enabled</li>
            <li>Logging destination not configured</li>
          </ul>
        </div>
      </div>
    </div>
  )
}

function AuditLogsPage() {
  const logs = getAuditLogs()
  const [dateFilter, setDateFilter] = useState('All')
  const [userFilter, setUserFilter] = useState('All')
  const [actionFilter, setActionFilter] = useState('All')
  const [resultFilter, setResultFilter] = useState('All')

  const filtered = logs.filter((log) => {
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

function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:id" element={<DeviceDetailsPage />} />
        <Route path="/configuration" element={<ConfigurationPage />} />
        <Route path="/analysis" element={<AnalysisPage />} />
        <Route path="/analysis/:id" element={<AnalysisDetailsPage />} />
        <Route path="/compliance" element={<CompliancePage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:id" element={<FindingDetailsPage />} />
        <Route path="/remediation" element={<RemediationPage />} />
        <Route path="/training" element={<TrainingPage />} />
        <Route path="/frameworks" element={<FrameworksPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/audit-logs" element={<AuditLogsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  )
}

export default App
