import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { apiClient } from '@/lib/api-client'

export function useHealthQuery() {
  return useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => apiClient.health(signal),
    refetchInterval: 15_000,
    retry: 2,
    staleTime: 5_000,
  })
}

export function useDashboardStatsQuery() {
  return useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: ({ signal }) => apiClient.dashboardStats(signal),
    refetchInterval: 15_000,
    retry: 2,
  })
}

export function useSystemInfoQuery() {
  return useQuery({
    queryKey: ['system-info'],
    queryFn: ({ signal }) => apiClient.systemInfo(signal),
    retry: 2,
  })
}

export function useToolsQuery() {
  return useQuery({
    queryKey: ['system-tools'],
    queryFn: ({ signal }) => apiClient.tools(signal),
    retry: 2,
  })
}

// ---------------------------------------------------------------------------
// Captures
// ---------------------------------------------------------------------------

export function useCapturesQuery(page = 1) {
  return useQuery({
    queryKey: ['captures', page],
    queryFn: ({ signal }) => apiClient.listCaptures(page, signal),
    placeholderData: (prev) => prev,
  })
}

export function useCaptureQuery(captureKey: string | undefined) {
  return useQuery({
    queryKey: ['capture', captureKey],
    queryFn: ({ signal }) => apiClient.getCapture(captureKey as string, signal),
    enabled: Boolean(captureKey),
  })
}

export function useAnalyzeCaptureMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (captureKey: string) => apiClient.analyzeCapture(captureKey),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['captures'] })
      void queryClient.invalidateQueries({ queryKey: ['analysis-jobs'] })
      void queryClient.invalidateQueries({ queryKey: ['analyses'] })
    },
  })
}

export function useDeleteCaptureMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (captureKey: string) => apiClient.deleteCapture(captureKey),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['captures'] })
      void queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] })
    },
  })
}

// ---------------------------------------------------------------------------
// Analyses & jobs
// ---------------------------------------------------------------------------

export function useJobsQuery(page = 1, refetchIntervalMs?: number) {
  return useQuery({
    queryKey: ['analysis-jobs', page],
    queryFn: ({ signal }) => apiClient.listJobs(page, signal),
    refetchInterval: refetchIntervalMs,
  })
}

export function useAnalysesQuery(page = 1, refetchIntervalMs?: number) {
  return useQuery({
    queryKey: ['analyses', page],
    queryFn: ({ signal }) => apiClient.listAnalyses(page, signal),
    refetchInterval: refetchIntervalMs,
    placeholderData: (prev) => prev,
  })
}

export function useAnalysisQuery(analysisKey: string | undefined, refetchIntervalMs?: number) {
  return useQuery({
    queryKey: ['analysis', analysisKey],
    queryFn: ({ signal }) => apiClient.getAnalysis(analysisKey as string, signal),
    enabled: Boolean(analysisKey),
    refetchInterval: refetchIntervalMs,
  })
}

// ---------------------------------------------------------------------------
// Sub-resources
// ---------------------------------------------------------------------------

export function useProtocolObservationsQuery(analysisKey: string | undefined) {
  return useQuery({
    queryKey: ['analysis-observations', analysisKey],
    queryFn: ({ signal }) =>
      apiClient.listProtocolObservations(analysisKey as string, 1, signal),
    enabled: Boolean(analysisKey),
  })
}

export function useIkeMessagesQuery(analysisKey: string | undefined) {
  return useQuery({
    queryKey: ['analysis-ike', analysisKey],
    queryFn: ({ signal }) => apiClient.listIkeMessages(analysisKey as string, 1, signal),
    enabled: Boolean(analysisKey),
  })
}

export function useEspPacketsQuery(analysisKey: string | undefined) {
  return useQuery({
    queryKey: ['analysis-esp', analysisKey],
    queryFn: ({ signal }) => apiClient.listEspPackets(analysisKey as string, 1, signal),
    enabled: Boolean(analysisKey),
  })
}

export function useAhPacketsQuery(analysisKey: string | undefined) {
  return useQuery({
    queryKey: ['analysis-ah', analysisKey],
    queryFn: ({ signal }) => apiClient.listAhPackets(analysisKey as string, 1, signal),
    enabled: Boolean(analysisKey),
  })
}

export function useFlowsQuery(analysisKey: string | undefined) {
  return useQuery({
    queryKey: ['analysis-flows', analysisKey],
    queryFn: ({ signal }) => apiClient.listFlows(analysisKey as string, 1, signal),
    enabled: Boolean(analysisKey),
  })
}

export function useFlowFeaturesQuery(analysisKey: string | undefined) {
  return useQuery({
    queryKey: ['analysis-features', analysisKey],
    queryFn: ({ signal }) => apiClient.listFlowFeatures(analysisKey as string, 1, signal),
    enabled: Boolean(analysisKey),
  })
}

// ---------------------------------------------------------------------------
// Phase 3 — Security assessment
// ---------------------------------------------------------------------------

export function useFindingsQuery(analysisKey: string | undefined) {
  return useQuery({
    queryKey: ['analysis-findings', analysisKey],
    queryFn: ({ signal }) => apiClient.listFindings(analysisKey as string, 1, signal),
    enabled: Boolean(analysisKey),
  })
}

/** Findings across every analysis, for the global Findings page. */
export function useAllFindingsQuery(page = 1) {
  return useQuery({
    queryKey: ['all-findings', page],
    queryFn: ({ signal }) => apiClient.listAllFindings(page, 50, signal),
    placeholderData: (prev) => prev,
  })
}

export function useAssessMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (analysisKey: string) => apiClient.assessAnalysis(analysisKey),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['analysis-findings'] })
      void queryClient.invalidateQueries({ queryKey: ['analysis'] })
      void queryClient.invalidateQueries({ queryKey: ['analyses'] })
      void queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] })
    },
  })
}