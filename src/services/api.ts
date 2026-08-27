// vendorOptions was used by UI; remove unused import to avoid TS warning
import type {
  AnalysisJob,
  AnalysisResult,
  Device,
  Finding,
  FrameworkDefinition,
  ReportItem,
  TrainingItem,
  UploadRecord,
} from '../types'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api'
const runtimeJobs: AnalysisJob[] = []
const runtimeResults: AnalysisResult[] = []

async function request<T>(path: string): Promise<T> {
  const response = await fetch(`${API_URL}${path}`)
  if (!response.ok) throw new Error('The compliance API is unavailable. Start the backend and try again.')
  return response.json() as Promise<T>
}

export const getLiveDashboard = () => request<{
  totalDevices: number; configurationsAnalyzed: number; overallScore: number; openFindings: number
  severityBreakdown: { name: string; value: number }[]
  recentActivity: { id: string; device: string; vendor: string; framework: string; score: number; status: string; date: string }[]
  vendorCompliance: { name: string; score: number }[]
  frameworkComparison: { name: string; score: number }[]
}>('/dashboard')
export const getLiveDevices = () => request<Device[]>('/devices')
export const getLiveFindings = () => request<Finding[]>('/findings')
export const getLiveReports = () => request<ReportItem[]>('/reports')
export const getLiveAnalyses = () => request<any[]>('/analyses')
export const getLiveTrainingMappings = () => request<any[]>('/training-mappings')
export const reportUrl = (analysisId: string) => `${API_URL}/analyses/${analysisId}/report.pdf`
// helper: fetch dashboard-shaped stats from backend
export const getDashboardStats = async () => {
  const [live, findings] = await Promise.all([
    getLiveDashboard(),
    getLiveFindings(),
  ])

  const criticalFindings = findings.filter(
    (finding: any) => finding.severity === 'Critical'
  )

  const trend = live.recentActivity
    .slice()
    .reverse()
    .map((item) => ({
      name: new Date(item.date).toLocaleDateString('en-IN', {
        day: '2-digit',
        month: 'short',
      }),
      score: item.score,
    }))

  return {
    snapshot: {
      totalDevices: live.totalDevices,
      configurationsAnalyzed: live.configurationsAnalyzed,
      overallScore: live.overallScore,
      openFindings: live.openFindings,
      lastAnalysis:
        live.recentActivity[0]?.date ?? 'No scans yet',
    },

    trend,

    severityBreakdown: live.severityBreakdown,

    vendorCompliance: live.vendorCompliance,

    frameworkComparison: live.frameworkComparison,

    recentActivity: live.recentActivity.map((item) => ({
      ...item,
      analysis: `${item.framework} analysis`,
    })),

    criticalFindings,
  }
}

export const getDevices = () => getLiveDevices()

export const getDevice = async (id: string) => {
  const items = await getLiveDevices()
  return items.find((d) => d.id === id)
}

export const uploadConfiguration = (fileName: string, vendor?: string): UploadRecord => ({
  id: `file-${Date.now()}`,
  filename: fileName,
  size: '412 KB',
  detectedVendor: vendor ?? 'Cisco',
  deviceType: 'Router',
  status: 'Detected',
})

export const startAnalysis = async (file: File, vendor: string, framework: string, inventory: { model?: string; serial?: string; ipAddress?: string } = {}): Promise<{ job: AnalysisJob; result: AnalysisResult }> => {
  const form = new FormData()
  form.append('file', file)
  form.append('vendor', vendor)
  form.append('framework', framework)
  form.append('device_model', inventory.model ?? '')
  form.append('device_serial', inventory.serial ?? '')
  form.append('device_ip', inventory.ipAddress ?? '')
  const response = await fetch(`${API_URL}/analyses/upload`, { method: 'POST', body: form })
  if (!response.ok) {
    const details = await response.json().catch(() => null)
    throw new Error(details?.detail ?? 'The compliance API could not analyze this file.')
  }
  const analysis = await response.json()
  const job: AnalysisJob = {
    id: analysis.id,
    fileName: analysis.fileName,
    device: analysis.fileName.replace(/\.[^.]+$/, ''),
    vendor: analysis.vendor,
    framework: analysis.framework,
    progress: 100,
    status: 'Completed',
    started: analysis.createdAt,
    completed: analysis.createdAt,
  }

  const result: AnalysisResult = {
    id: analysis.id,
    jobId: job.id,
    device: job.device,
    vendor: analysis.vendor,
    framework: analysis.framework,
    overallScore: analysis.overallScore,
    riskLevel: analysis.riskLevel,
    controlsChecked: analysis.controlsChecked,
    passed: analysis.passed,
    failed: analysis.failed,
    warnings: analysis.warnings,
    summary: analysis.summary,
    timestamp: analysis.createdAt,
    controls: analysis.controls,
  }
  runtimeJobs.unshift(job)
  runtimeResults.unshift(result)
  return { job, result }
}

export const startAnalysisBatch = async (files: File[], vendor: string, framework: string, inventory: { model?: string; serial?: string; ipAddress?: string } = {}) => {
  const form = new FormData()
  files.forEach((file) => form.append('files', file))
  form.append('vendor', vendor)
  form.append('framework', framework)
  form.append('device_model', inventory.model ?? '')
  form.append('device_serial', inventory.serial ?? '')
  form.append('device_ip', inventory.ipAddress ?? '')
  const response = await fetch(`${API_URL}/analyses/upload-batch`, { method: 'POST', body: form })
  if (!response.ok) {
    const details = await response.json().catch(() => null)
    throw new Error(details?.detail ?? 'The compliance API could not analyze these files.')
  }
  return response.json() as Promise<any[]>
}


export const getAnalysisJobs = () => getLiveAnalyses()

export const getAnalysisResult = (id: string) => request<any>(`/analyses/${id}`)

export const getFindings = () => getLiveFindings()

export const getFinding = async (id: string) => {
  const items = await getLiveFindings()
  return items.find((f) => f.id === id)
}

export const getRemediations = async () => {
  const findings = await getLiveFindings()
  // map top findings into remediation tasks
  return findings.slice(0, 20).map((f: any, idx: number) => ({
    id: `rem-${idx}-${f.id}`,
    finding: f.title,
    device: f.device,
    severity: f.severity,
    type: 'Configuration Change',
    command: f.remediationCommand ?? f.action ?? '',
    status: 'Pending',
  }))
}

export const getTrainingItems = () => getLiveTrainingMappings()

export const saveTrainingMapping = async (payload: Partial<TrainingItem>): Promise<TrainingItem> => {
  const response = await fetch(`${API_URL}/training-mappings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      raw_command: payload.command ?? 'set management access legacy-protocol enable',
      vendor: payload.vendor ?? 'Unknown Vendor',
      field_name: payload.mapping ?? 'telnet_disabled',
      observed_value: payload.observedValue ?? false,
      meaning: payload.meaning ?? 'Administrator-provided vendor syntax mapping.',
      confidence: payload.confidence ?? 92,
    }),
  })
  if (!response.ok) {
    const details = await response.json().catch(() => null)
    throw new Error(details?.detail ?? 'The training mapping could not be saved.')
  }
  const saved = await response.json()
  return {
    id: saved.id,
    command: saved.raw_command,
    vendor: saved.vendor,
    mapping: saved.field_name,
    framework: payload.framework ?? 'CIS',
    confidence: saved.confidence,
    createdBy: payload.createdBy ?? 'Admin',
    date: saved.created_at.slice(0, 10),
    category: payload.category ?? 'Management Access',
    parameter: payload.parameter ?? saved.field_name,
    meaning: saved.meaning,
    expectedSecureValue: String(payload.expectedSecureValue ?? ''),
    observedValue: saved.observed_value,
  }
}

export const applyTrainingMappings = async () => {
  const response = await fetch(`${API_URL}/training-mappings/apply`, { method: 'POST' })
  if (!response.ok) throw new Error('Could not apply training mappings')
  return response.json()
}

export const getFrameworks = () => request<FrameworkDefinition[]>('/frameworks')

export const getReports = () => getLiveReports()

export const getAuditLogs = async () => {
  // Derive a lightweight audit log view from training mappings and analyses
  try {
    const mappings = await getLiveTrainingMappings()
    const analyses = await getLiveAnalyses()
    const mapLogs = (mappings || []).map((m: any, idx: number) => ({ id: `log-m-${idx}`, timestamp: m.created_at, user: 'Admin', action: 'AI mapping created', resource: m.raw_command, device: 'Unknown', result: 'Success', ipAddress: '127.0.0.1' }))
    const analysisLogs = (analyses || []).slice(0, 20).map((a: any, idx: number) => ({ id: `log-a-${idx}`, timestamp: a.createdAt ?? a.created_at ?? new Date().toISOString(), user: 'System', action: 'Analysis completed', resource: a.fileName ?? a.filename ?? a.id, device: a.fileName?.replace(/\.[^.]+$/, '') ?? a.id, result: 'Success', ipAddress: '127.0.0.1' }))
    return [...analysisLogs, ...mapLogs].sort((x, y) => new Date(y.timestamp).getTime() - new Date(x.timestamp).getTime())
  } catch (e) {
    return []
  }
}

export const getUploadedFiles = async () => {
  try {
    const analyses = await getLiveAnalyses()
    return (analyses || []).map((a: any) => ({ id: a.id, filename: a.fileName ?? a.filename ?? a.id, size: 'n/a', detectedVendor: a.vendor ?? 'Unknown', deviceType: 'Network device', status: 'Ready', uploadUrl: a.upload_url ?? `/api/analyses/${a.id}/raw` }))
  } catch (e) {
    return []
  }
}

export const rawUrl = (analysisId: string) => `${API_URL}/analyses/${analysisId}/raw`

export const getStorageInfo = async () => {
  const info = await request<{ supabase_configured: boolean; supabase_bucket?: string }>('/storage-info')
  return {
    s3_configured: info.supabase_configured,
    s3_bucket: info.supabase_bucket,
  }
}

export const reRunUploadedAnalysis = async (analysisId: string, framework = 'CIS Benchmarks') => {
  // download raw content then POST as a file to startAnalysis
  const rawResponse = await fetch(rawUrl(analysisId))
  if (!rawResponse.ok) throw new Error('Could not fetch raw uploaded file')
  const text = await rawResponse.text()
  const filename = `${analysisId}.cfg`
  const file = new File([text], filename, { type: 'text/plain' })
  // vendor is not known reliably here; let backend detect vendor automatically via vendor='Auto'
  return startAnalysis(file, 'Auto', framework)
}
