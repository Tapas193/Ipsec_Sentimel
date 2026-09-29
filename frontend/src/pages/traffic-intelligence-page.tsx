import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Database, FlaskConical, Loader2, Network, Play, RefreshCw, ScrollText, Trash2,
} from 'lucide-react'

import { EmptyState } from '@/components/empty-state'
import { ErrorCard, LoadingCard } from '@/components/feedback'
import {
  MLDatasetReportCard, MLMetricsPanel, MLModelRegistry, MLPredictionStats, MLPredictionsTable,
  MLStateCard, MLUnavailableCard,
} from '@/components/ml-predictions'
import { StatusBadge } from '@/components/status-badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  useAnalysesQuery, useDeletePredictionsMutation, useMLDatasetQuery, useMLHealthQuery,
  useMLModelMetricsQuery, useMLModelsQuery, useMLPredictionsQuery, useRunPredictionMutation,
  useTrainModelMutation,
} from '@/hooks/use-api'
import { ApiClientError } from '@/lib/api-client'
import { formatConfidence, mlGateState, mlStatusExplanation } from '@/lib/ml'
import type { MLHealth, MLModel, PredictionSummary } from '@/types/api'

const EMPTY_SUMMARY: PredictionSummary = {
  count: 0,
  model_version: null,
  average_confidence: null,
  unknown_count: 0,
  abstained_count: 0,
  low_confidence_count: 0,
  class_distribution: {},
}

/**
 * Traffic Intelligence — the Phase 4 landing page.
 *
 * Written around one assumption: there is normally no model. This repository
 * ships no ground truth, so the default path is a fully explained "no model"
 * view rather than a spinner, a bare empty table, or an error banner. Training,
 * inference and history stay reachable, but each is labelled with what it would
 * and would not do.
 */
export function TrafficIntelligencePage() {
  const health = useMLHealthQuery()
  const models = useMLModelsQuery()
  const dataset = useMLDatasetQuery()
  const [selectedModel, setSelectedModel] = useState<string | null>(null)

  const gate = mlGateState(health.data, dataset.data)
  const activeVersion = models.data?.active_model_version ?? null
  const inspectedVersion = selectedModel ?? activeVersion
  const metrics = useMLModelMetricsQuery(inspectedVersion ?? undefined)

  return (
    <div className="space-y-6">
      <section className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground">Traffic Intelligence</h2>
          <p className="text-sm text-muted-foreground">
            Supervised flow classification over the Phase 2 feature schema. Predictions are
            informational and never affect security findings or risk scores.
          </p>
        </div>
        {health.isPending ? (
          <StatusBadge value="loading" kind="ml" />
        ) : health.isError ? (
          <StatusBadge value="unreachable" kind="ml" />
        ) : (
          <StatusBadge
            value={health.data?.ml_enabled ? (activeVersion ?? 'MODEL_NOT_AVAILABLE') : 'DISABLED'}
            kind="ml"
          />
        )}
      </section>

      {health.isError ? (
        <ErrorCard message="The ML subsystem could not be reached from the API." />
      ) : null}

      {health.isPending ? <LoadingCard /> : null}
      {health.data ? <MLHealthOverview health={health.data} /> : null}

      {gate === 'disabled' ? (
        <MLStateCard
          status="DISABLED"
          title="Traffic classification is disabled"
          action={
            <p className="text-xs text-muted-foreground">
              Set <span className="font-mono">ML_ENABLED=true</span> on the backend to enable
              inference, and <span className="font-mono">ML_TRAINING_ENABLED=true</span> to enable
              training.
            </p>
          }
        />
      ) : null}

      {gate === 'no-model' ? (
        <MLUnavailableCard
          status={health.data?.ml_enabled ? 'MODEL_NOT_AVAILABLE' : 'DISABLED'}
          detail={health.data?.detail ?? null}
        />
      ) : null}

      <TrainingPanel
        enabled={health.data?.training_enabled ?? false}
        datasetRefused={dataset.data?.status}
      />

      {dataset.isPending ? <LoadingCard /> : null}
      {dataset.isError ? <ErrorCard message="The dataset dry run could not be loaded." /> : null}
      {dataset.data ? <MLDatasetReportCard dataset={dataset.data} /> : null}

      <ModelSection
        models={models.data?.models ?? []}
        activeVersion={activeVersion}
        inspectedVersion={inspectedVersion}
        pending={models.isPending}
        errored={models.isError}
        onSelect={setSelectedModel}
        metrics={metrics.data}
        metricsPending={metrics.isPending && Boolean(inspectedVersion)}
        metricsErrored={metrics.isError}
      />

      {gate === 'ready' ? <PredictionSection activeModelVersion={activeVersion} /> : null}

      <FeatureContractCard />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

function MLHealthOverview({ health }: { health: MLHealth }) {
  const rows: Array<[string, string]> = [
    ['ML enabled', health.ml_enabled ? 'yes' : 'no'],
    ['Training enabled', health.training_enabled ? 'yes' : 'no'],
    ['Active model', health.active_model_version ?? '—'],
    ['Registered models', health.models.join(', ') || '—'],
    ['Feature schema version', health.feature_schema_version],
    ['Dataset version', health.dataset_version],
    ['Active classes', String(health.class_count)],
    ['Abstention threshold', formatConfidence(health.min_confidence)],
  ]
  return (
    <Card>
      <CardHeader>
        <CardTitle>Subsystem readiness</CardTitle>
        <CardDescription>
          A model is only reported active when a registered artifact matches the current feature
          schema version. Anything else is MODEL_NOT_AVAILABLE.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          {rows.map(([label, value]) => (
            <div key={label} className="space-y-0.5">
              <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
              <dd className="break-words font-mono text-xs text-foreground">{value}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Training
// ---------------------------------------------------------------------------

function TrainingPanel({
  enabled,
  datasetRefused,
}: {
  enabled: boolean
  datasetRefused: string | undefined
}) {
  const train = useTrainModelMutation()
  const result = train.data

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <FlaskConical className="h-4 w-4 text-brand" /> Training
            </CardTitle>
            <CardDescription>
              Training requires an operator-supplied ground-truth label file. There is no code path
              that derives labels from captures, ports or heuristics.
            </CardDescription>
          </div>
          <div className="flex flex-col items-end gap-1">
            <Button onClick={() => train.mutate({})} disabled={!enabled || train.isPending}>
              {train.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <RefreshCw className="h-3.5 w-3.5" />
              )}
              Train model
            </Button>
            <p className="text-xs text-muted-foreground">
              {enabled ? 'Uses ML_LABEL_FILE on the backend host' : 'ML_TRAINING_ENABLED is false'}
            </p>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {train.isError ? (
          <ErrorCard
            message={
              train.error instanceof ApiClientError
                ? `${train.error.message} (${train.error.code})`
                : 'The training request failed.'
            }
          />
        ) : null}

        {result ? <TrainingResultPanel result={result} /> : null}

        {!result && !train.isError ? (
          <p className="text-xs text-muted-foreground">
            {mlStatusExplanation(datasetRefused ?? 'NO_LABELS_REGISTERED')}
          </p>
        ) : null}
      </CardContent>
    </Card>
  )
}

function TrainingResultPanel({
  result,
}: {
  result: NonNullable<ReturnType<typeof useTrainModelMutation>['data']>
}) {
  const provenance = Object.entries(result.label_provenance)
    .map(([source, count]) => `${source} × ${count}`)
    .join(', ')

  return (
    <div className="space-y-3 rounded-md border border-border bg-secondary/30 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge value={result.status} kind="ml" />
        <span className="text-sm text-foreground">{result.message}</span>
      </div>
      <p className="text-xs text-muted-foreground">{mlStatusExplanation(result.status)}</p>
      {result.trained ? (
        <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Model version" value={result.model_version} />
          <Field label="Dataset version" value={result.dataset_version} />
          <Field label="Feature schema" value={result.feature_schema_version} />
          <Field label="Training samples" value={String(result.training_samples)} />
          <Field label="Captures used" value={String(result.capture_count)} />
          <Field label="Classes" value={result.classes.join(', ') || '—'} />
          <Field label="Label provenance" value={provenance || '—'} />
          <Field
            label="Duration"
            value={
              result.duration_seconds === null ? '—' : `${result.duration_seconds.toFixed(2)} s`
            }
          />
        </dl>
      ) : (
        <p className="text-xs text-muted-foreground">
          No artifact was written. {result.rejected_rows} row(s) would have been rejected.
        </p>
      )}
      <p className="text-xs text-muted-foreground">
        The dataset version and digest are recorded with every artifact, so a result can be traced
        back to the exact features and labels that produced it.
      </p>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

function ModelSection({
  models,
  activeVersion,
  inspectedVersion,
  pending,
  errored,
  onSelect,
  metrics,
  metricsPending,
  metricsErrored,
}: {
  models: MLModel[]
  activeVersion: string | null
  inspectedVersion: string | null
  pending: boolean
  errored: boolean
  onSelect: (version: string) => void
  metrics: ReturnType<typeof useMLModelMetricsQuery>['data']
  metricsPending: boolean
  metricsErrored: boolean
}) {
  return (
    <div className="space-y-4">
      {pending ? <LoadingCard /> : null}
      {errored ? <ErrorCard message="The model registry could not be loaded." /> : null}

      {models.length === 0 && !pending && !errored ? (
        <EmptyState
          icon={Database}
          title="No trained models"
          description="The model directory is empty. No pre-trained weights ship with this project, and an artifact is written only after a training run completes against a registered label set."
        />
      ) : null}

      {models.length > 0 ? (
        <MLModelRegistry
          models={models}
          activeVersion={activeVersion}
          selectedVersion={inspectedVersion}
          onSelect={onSelect}
        />
      ) : null}

      {metricsPending ? <LoadingCard /> : null}
      {metricsErrored ? <ErrorCard message="Model metrics could not be loaded." /> : null}
      {metrics ? (
        <MLMetricsPanel
          metrics={metrics.metrics}
          note={metrics.note}
          modelVersion={metrics.model_version}
        />
      ) : null}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Predictions
// ---------------------------------------------------------------------------

function PredictionSection({ activeModelVersion }: { activeModelVersion: string | null }) {
  const analyses = useAnalysesQuery(1)
  const [analysisKey, setAnalysisKey] = useState<string>('')
  const run = useRunPredictionMutation()
  const clear = useDeletePredictionsMutation()
  const predictions = useMLPredictionsQuery(
    analysisKey || undefined,
    activeModelVersion ?? undefined,
  )

  const runResult = run.data
  const rows = predictions.data?.predictions ?? []

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Play className="h-4 w-4 text-brand" /> Inference
              </CardTitle>
              <CardDescription>
                Scoring is idempotent: re-running for the same model version updates the existing
                rows rather than appending duplicates.
              </CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={analysisKey}
                onChange={(event) => setAnalysisKey(event.target.value)}
                className="h-8 rounded-md border border-border bg-background px-2 text-xs text-foreground"
                aria-label="Analysis to score"
              >
                <option value="">Select an analysis…</option>
                {(analyses.data?.items ?? []).map((analysis) => (
                  <option key={analysis.id} value={analysis.analysis_id ?? analysis.id}>
                    {analysis.analysis_id ?? analysis.id}
                    {analysis.status ? ` · ${analysis.status}` : ''}
                  </option>
                ))}
              </select>
              <Button
                size="sm"
                onClick={() => run.mutate({ analysisKey })}
                disabled={!analysisKey || run.isPending}
              >
                {run.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Play className="h-3.5 w-3.5" />
                )}
                Run inference
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => clear.mutate(analysisKey)}
                disabled={!analysisKey || clear.isPending}
              >
                {clear.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Trash2 className="h-3.5 w-3.5" />
                )}
                Clear predictions
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {run.isError ? (
            <ErrorCard
              message={
                run.error instanceof ApiClientError ? run.error.message : 'Inference failed.'
              }
            />
          ) : null}
          {runResult ? (
            <div className="space-y-2 rounded-md border border-border bg-secondary/30 px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge value={runResult.status} kind="ml" />
                <span className="text-sm text-foreground">
                  {runResult.created} created · {runResult.updated} updated · {runResult.rejected}{' '}
                  rejected of {runResult.total} flows
                </span>
              </div>
              <p className="text-xs text-muted-foreground">{mlStatusExplanation(runResult.status)}</p>
              <p className="text-xs text-muted-foreground">
                Every stored row is a{' '}
                <span className="font-mono">{runResult.observation_status}</span> observation. This
                is independent of the Phase 3 security assessment and changes no risk score.
              </p>
            </div>
          ) : null}
          {clear.data ? (
            <p className="text-xs text-muted-foreground">
              {clear.data.deleted} stored prediction row(s) removed.
            </p>
          ) : null}
        </CardContent>
      </Card>

      {analysisKey && predictions.isPending ? <LoadingCard /> : null}
      {analysisKey && predictions.isError ? (
        <ErrorCard message="Stored predictions could not be loaded." />
      ) : null}
      {analysisKey && !predictions.isPending && !predictions.isError ? (
        predictions.data?.status === 'INSUFFICIENT_DATA' ? (
          <MLStateCard status="INSUFFICIENT_DATA" title="Nothing to score" />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={Network}
            title="No stored predictions"
            description="This analysis has no persisted flow classifications yet. Run inference to score its flows, or check that a compatible model is registered."
            action={
              <Link to={`/analysis/${analysisKey}`} className="text-sm text-foreground hover:underline">
                Open the analysis detail
              </Link>
            }
          />
        ) : (
          <div className="space-y-4">
            <MLPredictionStats summary={predictions.data?.summary ?? EMPTY_SUMMARY} />
            <MLPredictionsTable rows={rows} />
          </div>
        )
      ) : null}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Feature contract
// ---------------------------------------------------------------------------

function FeatureContractCard() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ScrollText className="h-4 w-4 text-brand" /> Feature contract
        </CardTitle>
        <CardDescription>
          The approved feature set, frozen in{' '}
          <span className="font-mono">configs/ml_feature_schema.yaml</span>. A model trained against
          a different schema version is never used for inference.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-sm text-muted-foreground">
          The machine-readable contract is served from{' '}
          <span className="font-mono text-xs">GET /api/v1/ml/features</span>. The full field list,
          exclusions and split policy are documented in{' '}
          <span className="font-mono text-xs">docs/ml-dataset-plan.md</span>.
        </p>
      </CardContent>
    </Card>
  )
}

function Field({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="space-y-0.5">
      <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className="break-words font-mono text-xs text-foreground">{value || '—'}</dd>
    </div>
  )
}
