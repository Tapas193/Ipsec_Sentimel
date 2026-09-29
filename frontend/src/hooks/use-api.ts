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

// ---------------------------------------------------------------------------
// Phase 4 — ML / traffic classification
//
// None of these hooks are `enabled`-gated on a model existing. "No model yet"
// resolves to HTTP 200 with a status field, so gating on availability would
// leave the page permanently loading and would hide the explanation.
// ---------------------------------------------------------------------------

export function useMLHealthQuery() {
  return useQuery({
    queryKey: ['ml-health'],
    queryFn: ({ signal }) => apiClient.mlHealth(signal),
    retry: 2,
  })
}

export function useMLSchemaQuery() {
  return useQuery({
    queryKey: ['ml-schema'],
    queryFn: ({ signal }) => apiClient.mlSchema(signal),
  })
}

export function useMLFeaturesQuery() {
  return useQuery({
    queryKey: ['ml-features'],
    queryFn: ({ signal }) => apiClient.mlFeatures(signal),
  })
}

export function useMLModelsQuery() {
  return useQuery({
    queryKey: ['ml-models'],
    queryFn: ({ signal }) => apiClient.listModels(signal),
  })
}

export function useMLModelMetricsQuery(modelVersion: string | undefined) {
  return useQuery({
    queryKey: ['ml-model-metrics', modelVersion],
    queryFn: ({ signal }) => apiClient.getModelMetrics(modelVersion as string, signal),
    enabled: Boolean(modelVersion),
  })
}

export function useMLDatasetQuery() {
  return useQuery({
    queryKey: ['ml-dataset'],
    queryFn: ({ signal }) => apiClient.mlDataset(signal),
  })
}

export function useMLPredictionsQuery(
  analysisKey: string | undefined,
  modelVersion?: string,
) {
  return useQuery({
    queryKey: ['ml-predictions', analysisKey, modelVersion ?? null],
    queryFn: ({ signal }) => apiClient.listPredictions(analysisKey as string, modelVersion, signal),
    enabled: Boolean(analysisKey),
  })
}

export function useMLPredictionHistoryQuery(captureId?: string, limit = 50) {
  return useQuery({
    queryKey: ['ml-prediction-history', captureId ?? null, limit],
    queryFn: ({ signal }) => apiClient.predictionHistory(captureId, limit, signal),
  })
}

export function useRunPredictionMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ analysisKey, modelVersion }: { analysisKey: string; modelVersion?: string }) =>
      apiClient.runPrediction(analysisKey, modelVersion),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['ml-predictions'] })
      void queryClient.invalidateQueries({ queryKey: ['ml-prediction-history'] })
    },
  })
}

export function useDeletePredictionsMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (analysisKey: string) => apiClient.deletePredictions(analysisKey),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['ml-predictions'] })
      void queryClient.invalidateQueries({ queryKey: ['ml-prediction-history'] })
    },
  })
}

export function useTrainModelMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body?: { model_version?: string; label_file?: string }) =>
      apiClient.trainModel(body ?? {}),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['ml-models'] })
      void queryClient.invalidateQueries({ queryKey: ['ml-health'] })
      void queryClient.invalidateQueries({ queryKey: ['ml-dataset'] })
    },
  })
}