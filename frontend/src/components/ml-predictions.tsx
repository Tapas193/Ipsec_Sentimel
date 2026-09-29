import { useState } from 'react'
import type { ReactNode } from 'react'
import { BrainCircuit, ChevronDown, ChevronRight, FlaskConical, Info } from 'lucide-react'

import { EmptyState } from '@/components/empty-state'
import { SeverityStat } from '@/components/security-findings'
import { StatusBadge } from '@/components/status-badge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { cn, formatDateTime } from '@/lib/utils'
import {
  counterEntries,
  formatConfidence,
  formatMetric,
  formatSampleCount,
  mlRemediation,
  mlStatusExplanation,
  predictionLabel,
  predictionSubtitle,
  sortedProbabilities,
} from '@/lib/ml'
import type {
  MLDatasetReport,
  MLMetrics,
  MLModel,
  MLUnavailableDetail,
  PredictionSummary,
  TrafficPrediction,
} from '@/types/api'

/**
 * Shared ML presentation components.
 *
 * Split out from the pages so the Traffic Intelligence page and the per-analysis
 * ML tab render identical status language, metric placeholders and abstention
 * treatment. Only components are exported; every formatting rule lives in
 * `lib/ml.ts`.
 *
 * Two honesty rules are encoded structurally rather than by convention:
 *  - a metric the backend did not compute renders as "not measured", because the
 *    formatter takes `number | null` and has no way to print 0 for a gap;
 *  - an abstained row is labelled UNKNOWN while still exposing its runner-up,
 *    so a below-threshold guess can never be read as a classification.
 */

/** Explained empty state for DISABLED / MODEL_NOT_AVAILABLE / INSUFFICIENT_DATA. */
export function MLStateCard({
  status,
  title,
  action,
}: {
  status: string
  title?: string
  action?: ReactNode
}) {
  return (
    <EmptyState
      icon={status === 'DISABLED' ? Info : BrainCircuit}
      title={title ?? status.replace(/_/g, ' ')}
      description={mlStatusExplanation(status)}
      action={action}
    />
  )
}

/** ML state card that also surfaces the backend's remediation + provenance. */
export function MLUnavailableCard({
  status,
  detail,
  action,
}: {
  status: string
  detail: MLUnavailableDetail | null
  action?: ReactNode
}) {
  return (
    <Card className="border-dashed">
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <BrainCircuit className="h-5 w-5 text-muted-foreground" strokeWidth={1.5} />
          <CardTitle>No traffic model available</CardTitle>
          <StatusBadge value={status} kind="ml" />
        </div>
        <CardDescription>{mlStatusExplanation(status)}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {detail ? <UnavailableDetail detail={detail} /> : null}
        {action}
        <p className="text-xs text-muted-foreground">
          This project ships no pre-trained weights. A model appears here only after an operator
          supplies ground-truth labels and training completes against the feature schema below.
        </p>
      </CardContent>
    </Card>
  )
}

function UnavailableDetail({ detail }: { detail: MLUnavailableDetail }) {
  const rows: Array<[string, string]> = [
    ['Reason', detail.reason],
    ['Required feature schema', detail.required_feature_schema_version ?? '—'],
    ['Configured model', detail.configured_model_version ?? '—'],
    ['Registered models', detail.registered_model_versions.join(', ') || '—'],
    ['Remediation', mlRemediation(detail)],
  ]
  return (
    <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2">
      {rows.map(([label, value]) => (
        <div key={label} className="space-y-0.5">
          <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
          <dd className="break-words text-xs text-foreground">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

/** Count / mean-confidence / unknown / abstained roll-up for a prediction set. */
export function MLPredictionStats({ summary }: { summary: PredictionSummary }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      <SeverityStat label="Predictions" value={summary.count} />
      <SeverityStat
        label="Mean confidence"
        value={summary.average_confidence === null ? '—' : formatConfidence(summary.average_confidence)}
      />
      <SeverityStat label="Unknown" value={summary.unknown_count} variant="warning" />
      <SeverityStat label="Abstained" value={summary.abstained_count} variant="warning" />
      <SeverityStat label="Low confidence" value={summary.low_confidence_count} variant="info" />
    </div>
  )
}

/**
 * Per-flow predictions. Rows expand to the full class-probability vector, the
 * confidence threshold that decided the outcome, and the observation status.
 */
export function MLPredictionsTable({ rows }: { rows: TrafficPrediction[] }) {
  const [expanded, setExpanded] = useState<string | null>(null)
  return (
    <Card>
      <CardHeader>
        <CardTitle>Flow predictions</CardTitle>
        <CardDescription>
          One row per flow, scored by the active model. Rows below the confidence threshold are
          stored as UNKNOWN with the runner-up retained. Click a row for the full probability vector.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {rows.map((prediction) => {
          const isOpen = expanded === prediction.id
          return (
            <div key={prediction.id} className="rounded-md border border-border">
              <button
                type="button"
                onClick={() => setExpanded(isOpen ? null : prediction.id)}
                className="flex w-full flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5 text-left hover:bg-secondary/30"
              >
                {isOpen ? (
                  <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                )}
                <span className="font-mono text-xs text-muted-foreground">
                  {prediction.prediction_id ?? prediction.id.slice(0, 8)}
                </span>
                <span className="min-w-0 flex-1 truncate text-sm font-medium text-foreground">
                  {predictionLabel(prediction)}
                </span>
                <span className="text-xs text-muted-foreground">{predictionSubtitle(prediction)}</span>
                <Badge variant={prediction.abstained ? 'warning' : 'info'}>
                  {formatConfidence(prediction.confidence)}
                </Badge>
                {prediction.abstained ? <Badge variant="outline">abstained</Badge> : null}
                <span className="font-mono text-xs text-muted-foreground">
                  {prediction.flow_id.slice(0, 8)}
                </span>
              </button>
              {isOpen ? <PredictionDetail prediction={prediction} /> : null}
            </div>
          )
        })}
      </CardContent>
    </Card>
  )
}

function PredictionDetail({ prediction }: { prediction: TrafficPrediction }) {
  const probabilities = sortedProbabilities(prediction.probabilities)
  return (
    <div className="space-y-3 border-t border-border bg-secondary/20 px-4 py-3">
      <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
        <DetailField label="Flow UUID" value={prediction.flow_id} />
        <DetailField label="Capture" value={prediction.capture_id} />
        <DetailField label="Analysis" value={prediction.analysis_id} />
        <DetailField label="Model version" value={prediction.model_version} />
        <DetailField label="Model type" value={prediction.model_type} />
        <DetailField label="Dataset version" value={prediction.dataset_version} />
        <DetailField label="Feature schema" value={prediction.feature_schema_version} />
        <DetailField
          label="Confidence threshold"
          value={formatConfidence(prediction.min_confidence_threshold)}
        />
        <DetailField label="Observation status" value={prediction.observation_status} />
      </dl>
      <div className="space-y-1.5">
        <p className="text-xs uppercase tracking-wider text-muted-foreground">
          Class probabilities
        </p>
        {probabilities.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No probability vector was stored for this prediction.
          </p>
        ) : (
          <ul className="space-y-1">
            {probabilities.map((entry) => (
              <li key={entry.label} className="flex items-center gap-3">
                <span className="w-32 shrink-0 truncate font-mono text-xs text-foreground">
                  {entry.label}
                </span>
                <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-secondary">
                  <span
                    className="block h-full rounded-full bg-status-info"
                    style={{ width: `${Math.max(0, Math.min(1, entry.value)) * 100}%` }}
                  />
                </span>
                <span className="w-16 shrink-0 text-right font-mono text-xs text-muted-foreground">
                  {formatConfidence(entry.value)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function DetailField({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="space-y-0.5">
      <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className="break-words font-mono text-xs text-foreground">
        {value === null || value === undefined || value === '' ? '—' : value}
      </dd>
    </div>
  )
}

/**
 * Held-out metrics. Rendered only for a genuinely evaluated model; a model that
 * was fitted but not evaluated shows the backend's own note instead of zeros.
 */
export function MLMetricsPanel({
  metrics,
  note,
  modelVersion,
}: {
  metrics: MLMetrics | null
  note: string | null
  modelVersion: string
}) {
  if (!metrics) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Model metrics</CardTitle>
          <CardDescription>
            {note ??
              'This model was fitted but never evaluated: the held-out test split was too small. No metrics are claimed.'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 rounded-md border border-dashed border-border bg-secondary/30 px-4 py-3 text-sm text-muted-foreground">
            <Info className="h-4 w-4" /> No held-out metrics exist for {modelVersion}.
          </div>
        </CardContent>
      </Card>
    )
  }

  const headline: Array<[string, number | null]> = [
    ['Accuracy', metrics.accuracy],
    ['Precision (macro)', metrics.precision_macro],
    ['Recall (macro)', metrics.recall_macro],
    ['F1 (macro)', metrics.f1_macro],
  ]
  const calibration: Array<[string, number | null | undefined]> = [
    ['Mean predicted confidence', metrics.mean_predicted_confidence],
    ['Expected calibration error', metrics.expected_calibration_error],
    ['Abstention rate', metrics.abstention_rate],
  ]
  const classKeys = Object.keys(metrics.per_class)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Model metrics</CardTitle>
        <CardDescription>
          Measured on the held-out test split of {formatSampleCount(metrics.evaluated_samples)}{' '}
          samples. Values marked &ldquo;not measured&rdquo; were never computed.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {headline.map(([label, value]) => (
            <MetricTile key={label} label={label} value={value} />
          ))}
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {calibration.map(([label, value]) => (
            <MetricTile key={label} label={label} value={value} />
          ))}
        </div>
        {classKeys.length > 0 ? <PerClassMetrics metrics={metrics} /> : null}
        {metrics.confusion_matrix ? (
          <ConfusionMatrix metrics={metrics} />
        ) : (
          <p className="text-xs text-muted-foreground">
            No confusion matrix was recorded for this model.
          </p>
        )}
      </CardContent>
    </Card>
  )
}

function MetricTile({ label, value }: { label: string; value: number | null | undefined }) {
  const missing = value === null || value === undefined
  return (
    <div className="rounded-md border border-border bg-secondary/30 px-3 py-2">
      <p className="text-xs uppercase tracking-wider text-muted-foreground">{label}</p>
      <p
        className={cn(
          'mt-0.5 font-mono text-lg tabular-nums',
          missing ? 'text-xs text-muted-foreground' : 'text-foreground',
        )}
      >
        {missing ? 'not measured' : formatMetric(value)}
      </p>
    </div>
  )
}

function PerClassMetrics({ metrics }: { metrics: MLMetrics }) {
  return (
    <div className="space-y-2">
      <p className="text-xs uppercase tracking-wider text-muted-foreground">Per class</p>
      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
              <th className="py-2 pl-3 pr-3 font-medium">Class</th>
              <th className="py-2 pr-3 text-right font-medium">Precision</th>
              <th className="py-2 pr-3 text-right font-medium">Recall</th>
              <th className="py-2 pr-3 text-right font-medium">F1</th>
              <th className="py-2 pr-3 text-right font-medium">Support</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {Object.entries(metrics.per_class).map(([label, values]) => (
              <tr key={label}>
                <td className="py-1.5 pl-3 pr-3 font-mono text-foreground">{label}</td>
                <td className="py-1.5 pr-3 text-right font-mono text-muted-foreground">
                  {formatMetric(values.precision)}
                </td>
                <td className="py-1.5 pr-3 text-right font-mono text-muted-foreground">
                  {formatMetric(values.recall)}
                </td>
                <td className="py-1.5 pr-3 text-right font-mono text-muted-foreground">
                  {formatMetric(values.f1_score)}
                </td>
                <td className="py-1.5 pr-3 text-right font-mono text-muted-foreground">
                  {values.support === undefined ? '—' : values.support}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ConfusionMatrix({ metrics }: { metrics: MLMetrics }) {
  const matrix = metrics.confusion_matrix
  const labels = metrics.confusion_matrix_labels
  if (!matrix) return null
  return (
    <div className="space-y-2">
      <p className="text-xs uppercase tracking-wider text-muted-foreground">
        Confusion matrix (rows = actual, columns = predicted)
      </p>
      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
              <th className="py-2 pl-3 pr-3 font-medium">actual \ predicted</th>
              {labels.map((label) => (
                <th key={label} className="py-2 pr-3 text-right font-medium">
                  {label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {matrix.map((row, rowIndex) => (
              <tr key={labels[rowIndex] ?? rowIndex}>
                <td className="py-1.5 pl-3 pr-3 font-mono text-foreground">
                  {labels[rowIndex] ?? rowIndex}
                </td>
                {row.map((cell, cellIndex) => (
                  <td
                    key={labels[cellIndex] ?? cellIndex}
                    className={cn(
                      'py-1.5 pr-3 text-right font-mono',
                      rowIndex === cellIndex ? 'text-status-success' : 'text-muted-foreground',
                    )}
                  >
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** Registered models with the provenance needed to reproduce them. */
export function MLModelRegistry({
  models,
  activeVersion,
  onSelect,
  selectedVersion,
}: {
  models: MLModel[]
  activeVersion: string | null
  selectedVersion: string | null
  onSelect: (version: string) => void
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Model registry</CardTitle>
        <CardDescription>
          Every artifact carries the feature-schema version, dataset version and library versions it
          was built against, so a result can always be traced to its inputs.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {models.map((model) => {
          const isActive = model.model_version === activeVersion
          return (
            <div
              key={model.model_version}
              className={cn(
                'rounded-md border px-4 py-3',
                isActive ? 'border-status-success/40 bg-secondary/30' : 'border-border',
              )}
            >
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-mono text-sm font-medium text-foreground">
                  {model.model_version}
                </span>
                {isActive ? <Badge variant="success">active</Badge> : null}
                <Badge variant="outline">{model.model_type}</Badge>
                <span className="text-xs text-muted-foreground">
                  {model.training_samples} training samples · {model.feature_count} features
                </span>
                <span className="ml-auto text-xs text-muted-foreground">
                  {formatDateTime(model.created_at)}
                </span>
                <Button
                  size="sm"
                  variant={selectedVersion === model.model_version ? 'default' : 'outline'}
                  onClick={() => onSelect(model.model_version)}
                >
                  {selectedVersion === model.model_version ? 'Selected' : 'Inspect metrics'}
                </Button>
              </div>
              <dl className="mt-2 grid gap-x-8 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
                <DetailField label="Feature schema" value={model.feature_schema_version} />
                <DetailField label="Dataset version" value={model.dataset_version} />
                <DetailField label="Classes" value={model.classes.join(', ') || '—'} />
                <DetailField
                  label="Libraries"
                  value={
                    Object.entries(model.library_versions)
                      .map(([name, version]) => `${name} ${version}`)
                      .join(', ') || '—'
                  }
                />
              </dl>
              <p className="mt-2 text-xs text-muted-foreground">
                {model.metrics
                  ? `Held-out accuracy ${formatMetric(model.metrics.accuracy)}`
                  : 'No held-out metrics were computed for this model.'}
              </p>
            </div>
          )
        })}
      </CardContent>
    </Card>
  )
}

/** What training would see, without fitting anything. */
export function MLDatasetReportCard({ dataset }: { dataset: MLDatasetReport }) {
  const rows: Array<[string, string | null]> = [
    ['Status', dataset.status],
    ['Dataset version', dataset.dataset_version],
    ['Feature schema version', dataset.feature_schema_version],
    ['Class definition version', dataset.class_definition_version],
    ['Dataset digest', dataset.dataset_digest],
    ['Feature count', String(dataset.feature_count)],
    ['Total feature rows', dataset.total_feature_rows.toLocaleString()],
    ['Labeled rows', dataset.labeled_rows.toLocaleString()],
    ['Unlabeled rows', dataset.unlabeled_rows.toLocaleString()],
    ['Rejected rows', dataset.rejected_rows.toLocaleString()],
    ['Captures', dataset.capture_count.toLocaleString()],
    ['Labeled captures', dataset.labeled_capture_count.toLocaleString()],
    ['Label registry source', dataset.label_registry_source],
    ['Configured label file', dataset.label_file],
  ]
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <FlaskConical className="h-4 w-4 text-muted-foreground" />
          <CardTitle>Dataset dry run</CardTitle>
          <StatusBadge value={dataset.status} kind="ml" />
        </div>
        <CardDescription>
          What a training run would see, computed without fitting a model or writing an artifact.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
          {rows.map(([label, value]) => (
            <div key={label} className="space-y-0.5">
              <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
              <dd className="break-words font-mono text-xs text-foreground">
                {value === null || value === '' ? '—' : value}
              </dd>
            </div>
          ))}
        </dl>
        {counterEntries(dataset.class_distribution).length > 0 ? (
          <CounterChips title="Class distribution" counts={dataset.class_distribution} />
        ) : (
          <p className="text-xs text-muted-foreground">
            No labeled class distribution exists, so no class can be claimed as represented.
          </p>
        )}
        {counterEntries(dataset.rejection_reasons).length > 0 ? (
          <CounterChips title="Rejection reasons" counts={dataset.rejection_reasons} />
        ) : null}
        {dataset.notes.length > 0 ? (
          <ul className="list-inside list-disc space-y-1 text-xs text-muted-foreground">
            {dataset.notes.map((note, index) => (
              <li key={index}>{note}</li>
            ))}
          </ul>
        ) : null}
      </CardContent>
    </Card>
  )
}

function CounterChips({ title, counts }: { title: string; counts: Record<string, number> }) {
  return (
    <div className="space-y-1.5">
      <p className="text-xs uppercase tracking-wider text-muted-foreground">{title}</p>
      <div className="flex flex-wrap gap-1.5">
        {counterEntries(counts).map(([label, count]) => (
          <Badge key={label} variant="secondary" className="font-mono">
            {label} × {count}
          </Badge>
        ))}
      </div>
    </div>
  )
}
