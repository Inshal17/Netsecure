import {
  analysisJobs,
  analysisResults,
  auditLogs,
  complianceSnapshot,
  complianceTrend,
  devices,
  findings,
  frameworkComparison,
  frameworks,
  remediationTasks,
  reports,
  severityBreakdown,
  trainingItems,
  uploadedFiles,
  vendorCompliance,
} from './mockData'
import type {
  AnalysisJob,
  AnalysisResult,
  AuditLog,
  Device,
  Finding,
  FrameworkDefinition,
  ReportItem,
  RemediationTask,
  TrainingItem,
  UploadRecord,
} from '../types'

export const getDashboardStats = () => ({
  snapshot: complianceSnapshot,
  trend: complianceTrend,
  severityBreakdown,
  vendorCompliance,
  frameworkComparison,
  recentActivity: [
    { device: 'Core-Edge-01', vendor: 'Cisco', analysis: 'CIS Benchmark', framework: 'CIS Benchmarks', score: 92, status: 'Compliant', date: '2026-08-25' },
    { device: 'FW-Perimeter-A', vendor: 'Palo Alto', analysis: 'Access Review', framework: 'NIST SP 800-53', score: 78, status: 'Warning', date: '2026-08-25' },
    { device: 'FortiGate-Edge', vendor: 'Fortinet', analysis: 'ISO Baseline', framework: 'ISO/IEC 27001', score: 71, status: 'Non-Compliant', date: '2026-08-24' },
    { device: 'MX-Transit', vendor: 'Juniper', analysis: 'STIG Review', framework: 'DISA STIG', score: 57, status: 'Critical', date: '2026-08-24' },
  ],
  criticalFindings: findings.slice(0, 3),
})

export const getDevices = (): Device[] => devices

export const getDevice = (id: string): Device | undefined => devices.find((device) => device.id === id)

export const uploadConfiguration = (fileName: string, vendor?: string): UploadRecord => ({
  id: `file-${Date.now()}`,
  filename: fileName,
  size: '412 KB',
  detectedVendor: vendor ?? 'Cisco',
  deviceType: 'Router',
  status: 'Detected',
})

export const startAnalysis = (fileName: string, vendor: string, framework: string): { job: AnalysisJob; result: AnalysisResult } => {
  const job: AnalysisJob = {
    id: `job-${Date.now()}`,
    fileName,
    device: 'New Device',
    vendor,
    framework,
    progress: 100,
    status: 'Completed',
    started: new Date().toISOString(),
    completed: new Date().toISOString(),
  }

  const result: AnalysisResult = {
    id: `result-${Date.now()}`,
    jobId: job.id,
    device: 'New Device',
    vendor,
    framework,
    overallScore: 84,
    riskLevel: 'Moderate',
    controlsChecked: 20,
    passed: 15,
    failed: 3,
    warnings: 2,
    summary: 'The uploaded configuration was normalized and evaluated against the selected framework. Follow-up remediation is recommended for administrative access and logging hardening.',
    timestamp: new Date().toISOString(),
    controls: [
      { id: 'CIS-NET-01', framework: 'CIS', requirement: 'Disable legacy management protocols', result: 'Fail', severity: 'Critical', evidence: 'telnet enabled', remediation: 'Disable Telnet and enforce SSH version 2' },
      { id: 'CIS-NET-02', framework: 'CIS', requirement: 'Secure administrative access', result: 'Pass', severity: 'High', evidence: 'SSH version 2 configured', remediation: 'Maintain secure access policy' },
      { id: 'NIST-AU-02', framework: 'NIST', requirement: 'Centralized audit log export', result: 'Warning', severity: 'Medium', evidence: 'logging destination not configured', remediation: 'Configure logging host' },
    ],
  }

  return { job, result }
}

export const getAnalysisJobs = (): AnalysisJob[] => analysisJobs

export const getAnalysisResult = (id: string): AnalysisResult | undefined => analysisResults.find((result) => result.jobId === id || result.id === id)

export const getFindings = (): Finding[] => findings

export const getFinding = (id: string): Finding | undefined => findings.find((finding) => finding.id === id)

export const getRemediations = (): RemediationTask[] => remediationTasks

export const getTrainingItems = (): TrainingItem[] => trainingItems

export const saveTrainingMapping = (payload: Partial<TrainingItem>): TrainingItem => ({
  id: `train-${Date.now()}`,
  command: payload.command ?? 'set management access legacy-protocol enable',
  vendor: payload.vendor ?? 'Unknown Vendor',
  mapping: payload.mapping ?? 'legacy_protocol_disabled',
  framework: payload.framework ?? 'CIS',
  confidence: payload.confidence ?? 94,
  createdBy: payload.createdBy ?? 'A. Patel',
  date: new Date().toISOString().slice(0, 10),
  category: payload.category ?? 'Management Access',
  parameter: payload.parameter ?? 'insecure_protocol',
  meaning: payload.meaning ?? 'Enables a legacy protocol that exposes administrative access to clear-text channels.',
  expectedSecureValue: payload.expectedSecureValue ?? 'disabled',
})

export const getFrameworks = (): FrameworkDefinition[] => frameworks

export const getReports = (): ReportItem[] => reports

export const getAuditLogs = (): AuditLog[] => auditLogs

export const getUploadedFiles = (): UploadRecord[] => uploadedFiles
