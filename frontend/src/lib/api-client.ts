import type {
  AhPacket,
  Analysis,
  AnalysisJob,
  AnalysisSummary,
  AnalyzeResponse,
  ApiErrorBody,
  ApiResponse,
  AssessmentResult,
  Capture,
  DashboardStats,
  EspPacket,
  Flow,
  FlowFeatures,
  HealthData,
  IkeMessage,
  PaginatedData,
  ProtocolObservation,
  SecurityFinding,
  SystemInfoData,
  ToolStatus,
  ToolsData,
} from '@/types/api'

export class ApiClientError extends Error {
  status: number
  code: string
  details: Record<string, unknown> | null

  constructor(status: number, body: ApiErrorBody | null, fallbackMessage: string) {
    super(body?.message ?? fallbackMessage)
    this.name = 'ApiClientError'
    this.status = status
    this.code = body?.code ?? 'UNKNOWN_ERROR'
    this.details = body?.details ?? null
  }
}

const BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '/api/v1').replace(/\/$/, '')

async function request<T>(path: string, init?: RequestInit): Promise<ApiResponse<T>> {
  const response = await fetch(`${BASE_URL}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
    ...init,
  })

  const raw: unknown = await response.json().catch(() => null)

  if (!response.ok) {
    const body =
      raw && typeof raw === 'object' && 'error' in raw
        ? (raw as Pick<ApiResponse<never>, 'error'>).error
        : null
    throw new ApiClientError(response.status, body, `Request failed with ${response.status}`)
  }

  const envelope = raw as ApiResponse<T>
  if (!envelope.success || envelope.data === null) {
    throw new ApiClientError(response.status, envelope.error, 'Request returned no data')
  }
  return envelope
}

async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  const envelope = await request<T>(path, { signal })
  if (envelope.data === null) {
    throw new ApiClientError(200, envelope.error, 'Request returned no data')
  }
  return envelope.data
}

async function post<T>(path: string): Promise<T> {
  const envelope = await request<T>(path, { method: 'POST' })
  if (envelope.data === null) {
    throw new ApiClientError(200, envelope.error, 'Request returned no data')
  }
  return envelope.data
}

async function remove<T>(path: string): Promise<T> {
  const envelope = await request<T>(path, { method: 'DELETE' })
  if (envelope.data === null) {
    throw new ApiClientError(200, envelope.error, 'Request returned no data')
  }
  return envelope.data
}

/**
 * Upload a capture file as multipart form data with upload progress reporting.
 * Uses XMLHttpRequest (fetch does not expose upload progress).
 */
function uploadCapture(
  file: File,
  onProgress?: (percent: number) => void,
): Promise<Capture> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${BASE_URL}/captures`)
    xhr.responseType = 'text'

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable && onProgress) {
        onProgress(Math.round((event.loaded / event.total) * 100))
      }
    }

    xhr.onload = () => {
      try {
        const parsed = JSON.parse(xhr.responseText) as ApiResponse<Capture>
        if (xhr.status >= 200 && xhr.status < 300 && parsed.success && parsed.data) {
          resolve(parsed.data)
        } else {
          reject(
            new ApiClientError(xhr.status, parsed.error, `Upload failed with ${xhr.status}`),
          )
        }
      } catch {
        reject(
          new ApiClientError(
            xhr.status,
            null,
            `Upload failed with ${xhr.status}`,
          ),
        )
      }
    }

    xhr.onerror = () => reject(new ApiClientError(0, null, 'Upload failed (network error)'))
    xhr.onabort = () => reject(new ApiClientError(0, null, 'Upload aborted'))

    const form = new FormData()
    form.append('file', file)
    xhr.send(form)
  })
}

/**
 * Single typed API client for the entire frontend. Components never call
 * fetch directly — they use these methods (usually wrapped in React Query hooks).
 */
export const apiClient = {
  health: (signal?: AbortSignal) => get<HealthData>('/health', signal),
  dashboardStats: (signal?: AbortSignal) => get<DashboardStats>('/stats/dashboard', signal),
  systemInfo: (signal?: AbortSignal) => get<SystemInfoData>('/system/info', signal),
  tools: (signal?: AbortSignal) => get<ToolsData>('/system/tools', signal),

  // Captures
  listCaptures: (page = 1, signal?: AbortSignal) =>
    get<PaginatedData<Capture>>(`/captures?page=${page}`, signal),
  getCapture: (captureKey: string, signal?: AbortSignal) =>
    get<Capture>(`/captures/${captureKey}`, signal),
  uploadCapture,
  analyzeCapture: (captureKey: string) =>
    post<AnalyzeResponse>(`/captures/${captureKey}/analyze`),
  deleteCapture: (captureKey: string) => remove<Record<string, string>>(`/captures/${captureKey}`),

  // Analyses & jobs
  listJobs: (page = 1, signal?: AbortSignal) =>
    get<PaginatedData<AnalysisJob>>(`/analysis-jobs?page=${page}`, signal),
  getJob: (jobKey: string, signal?: AbortSignal) => get<AnalysisJob>(`/analysis-jobs/${jobKey}`, signal),
  listAnalyses: (page = 1, signal?: AbortSignal) =>
    get<PaginatedData<Analysis>>(`/analyses?page=${page}`, signal),
  getAnalysis: (analysisKey: string, signal?: AbortSignal) =>
    get<AnalysisSummary>(`/analyses/${analysisKey}`, signal),

  // Sub-resources
  listProtocolObservations: (analysisKey: string, page = 1, signal?: AbortSignal) =>
    get<PaginatedData<ProtocolObservation>>(
      `/analyses/${analysisKey}/protocol-observations?page=${page}`,
      signal,
    ),
  listIkeMessages: (analysisKey: string, page = 1, signal?: AbortSignal) =>
    get<PaginatedData<IkeMessage>>(`/analyses/${analysisKey}/ike-messages?page=${page}`, signal),
  listEspPackets: (analysisKey: string, page = 1, signal?: AbortSignal) =>
    get<PaginatedData<EspPacket>>(`/analyses/${analysisKey}/esp-packets?page=${page}`, signal),
  listAhPackets: (analysisKey: string, page = 1, signal?: AbortSignal) =>
    get<PaginatedData<AhPacket>>(`/analyses/${analysisKey}/ah-packets?page=${page}`, signal),
  listFlows: (analysisKey: string, page = 1, signal?: AbortSignal) =>
    get<PaginatedData<Flow>>(`/analyses/${analysisKey}/flows?page=${page}`, signal),
  listFlowFeatures: (analysisKey: string, page = 1, signal?: AbortSignal) =>
    get<PaginatedData<FlowFeatures>>(`/analyses/${analysisKey}/features?page=${page}`, signal),

  // Phase 3 — Security assessment
  listFindings: (analysisKey: string, page = 1, signal?: AbortSignal) =>
    get<PaginatedData<SecurityFinding>>(`/analyses/${analysisKey}/findings?page=${page}`, signal),
  getFinding: (analysisKey: string, findingKey: string, signal?: AbortSignal) =>
    get<SecurityFinding>(`/analyses/${analysisKey}/findings/${findingKey}`, signal),
  /** Every finding across every analysis, newest first. */
  listAllFindings: (page = 1, pageSize = 50, signal?: AbortSignal) =>
    get<PaginatedData<SecurityFinding>>(`/findings?page=${page}&page_size=${pageSize}`, signal),
  assessAnalysis: (analysisKey: string) =>
    post<AssessmentResult>(`/analyses/${analysisKey}/assess`),

  // Export URLs
  exportUrl: (analysisKey: string, resource: 'flows' | 'ike' | 'esp' | 'features') =>
    `${BASE_URL}/analyses/${analysisKey}/export/${resource}`,
}

export type { ToolStatus }