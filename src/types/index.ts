export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
export type RiskLevel = 'Critical' | 'High' | 'Moderate' | 'Low'
export type Status = 'Compliant' | 'Non-Compliant' | 'Warning' | 'Resolved' | 'Queued' | 'Processing' | 'Completed' | 'Failed' | 'Active' | 'Inactive'

export interface Device {
  id: string
  name: string
  vendor: string
  model: string
  serialNumber: string
  firmware: string
  ipAddress: string
  deviceType: string
  complianceScore: number
  risk: RiskLevel
  lastScan: string
  status: Status
  location: string
}

export interface ControlResult {
  id: string
  framework: string
  requirement: string
  result: 'Pass' | 'Fail' | 'Warning'
  severity: Severity
  evidence: string
  remediation: string
}

export interface AnalysisJob {
  id: string
  fileName: string
  device: string
  vendor: string
  framework: string
  progress: number
  status: 'Queued' | 'Processing' | 'Completed' | 'Failed'
  started: string
  completed: string | null
}

export interface AnalysisResult {
  id: string
  jobId: string
  device: string
  vendor: string
  framework: string
  overallScore: number
  riskLevel: RiskLevel
  controlsChecked: number
  passed: number
  failed: number
  warnings: number
  controls: ControlResult[]
  summary: string
  timestamp: string
}

export interface Finding {
  id: string
  title: string
  device: string
  vendor: string
  framework: string
  severity: Severity
  category: string
  status: 'Open' | 'Investigating' | 'Resolved' | 'Monitoring'
  detected: string
  action: string
  riskScore: number
  controlId: string
  description: string
  whyItMatters: string
  evidence: string
  currentConfig: string
  recommendedConfig: string
  remediationCommand: string
  references: string[]
}

export interface RemediationTask {
  id: string
  finding: string
  device: string
  severity: Severity
  type: string
  command: string
  status: 'Pending' | 'In Progress' | 'Completed'
}

export interface TrainingItem {
  id: string
  command: string
  vendor: string
  mapping: string
  framework: string
  confidence: number
  createdBy: string
  date: string
  category: string
  parameter: string
  meaning: string
  expectedSecureValue: string
}

export interface FrameworkDefinition {
  id: string
  name: string
  controls: number
  activeRules: number
  lastUpdated: string
  status: 'Healthy' | 'Monitoring' | 'Needs Review'
}

export interface ReportItem {
  id: string
  name: string
  device: string
  vendor: string
  framework: string
  complianceScore: number
  generatedDate: string
  status: 'Ready' | 'Draft' | 'Archived'
}

export interface AuditLog {
  id: string
  timestamp: string
  user: string
  action: string
  resource: string
  device: string
  result: 'Success' | 'Warning' | 'Failure'
  ipAddress: string
}

export interface UploadRecord {
  id: string
  filename: string
  size: string
  detectedVendor: string
  deviceType: string
  status: 'Detected' | 'Queued' | 'Analyzing'
}
