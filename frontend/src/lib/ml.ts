/**
 * Pure presentation logic for the Phase 4 ML views.
 *
 * Kept out of the component modules (the same reason `countBySeverity` lives in
 * `lib/findings.ts`): component files only export components, and the rules
 * about how an ML state is worded or coloured are shared by the Traffic
 * Intelligence page and the per-analysis ML tab, so they must not be able to
 * drift apart.
 *
 * The central rule these helpers enforce: a value the backend did not measure
 * is rendered as "not measured", never as `0` or `0.00`. A metric that was
 * never computed and a metric that computed to zero are different facts, and
 * collapsing them would misrepresent the model.
 */

import type {
  MLHealth,
  MLStatusTone,
  MLDatasetReport,
  MLUnavailableDetail,
  TrafficPrediction,
} from '@/types/api'

/** Not a measurement. Used wherever a number is missing by design. */
export const NOT_MEASURED = 'not measured'

/**
 * ML status tones, partitioned from the capture/finding/confidence maps in
 * `status-badge.tsx`. `MODEL_NOT_AVAILABLE` is deliberately `info`, never
 * `danger` or `warning`: an untrained model is the expected state of a system
 * with no ground truth, not a fault.
 */
const ML_TONE_BY_STATUS: Record<string, MLStatusTone> = {
  OK: 'success',
  DISABLED: 'secondary',
  MODEL_NOT_AVAILABLE: 'info',
  INSUFFICIENT_DATA: 'warning',
  INSUFFICIENT_LABELED_DATA: 'warning',
  NO_LABELS_REGISTERED: 'warning',
  LABEL_FILE_UNREADABLE: 'danger',
  FAILED: 'danger',
}

export function mlStatusTone(status: string | null | undefined): MLStatusTone {
  if (!status) return 'secondary'
  return ML_TONE_BY_STATUS[status.toUpperCase()] ?? 'secondary'
}

/** Short human sentence for an ML status, used as the empty-state body copy. */
export function mlStatusExplanation(status: string | null | undefined): string {
  switch (status?.toUpperCase()) {
    case 'DISABLED':
      return 'Machine learning is switched off on the server (ML_ENABLED is false). No training or inference is attempted.'
    case 'MODEL_NOT_AVAILABLE':
      return 'No trained model is registered yet. This project ships no pre-trained weights, and no model is fabricated from unlabeled captures.'
    case 'INSUFFICIENT_DATA':
      return 'This analysis has no flow features to score, so nothing was predicted.'
    case 'INSUFFICIENT_LABELED_DATA':
      return 'Training was refused because no ground-truth labels exist. Traffic classification cannot be validated from heuristics alone.'
    case 'NO_LABELS_REGISTERED':
      return 'No label registry is configured. Set ML_LABEL_FILE to a ground-truth file on the backend host to enable training.'
    case 'LABEL_FILE_UNREADABLE':
      return 'The configured label file could not be read, so training was refused rather than run on partial data.'
    case 'FAILED':
      return 'The ML operation failed. No artifact was written and no metrics are reported.'
    case 'OK':
      return 'A trained model produced predictions for these flows.'
    default:
      return 'The backend reported an unrecognised ML status.'
  }
}

/** Confidence as a percentage. `null` is a measurement gap, shown as an em dash. */
export function formatConfidence(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—'
  return `${(value * 100).toFixed(1)}%`
}

/**
 * A held-out metric. `null` means the model was never evaluated on that metric,
 * which is reported as "not measured" so it is never confused with a real 0.0.
 */
export function formatMetric(value: number | null | undefined, digits = 3): string {
  if (value === null || value === undefined) return NOT_MEASURED
  return value.toFixed(digits)
}

export function formatSampleCount(value: number | null | undefined): string {
  if (value === null || value === undefined) return NOT_MEASURED
  return value.toLocaleString()
}

/** Class probabilities, highest first, for the expandable row detail. */
export function sortedProbabilities(
  probabilities: Record<string, number>,
): Array<{ label: string; value: number }> {
  return Object.entries(probabilities)
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
}

/**
 * The label a prediction row should display. An abstained row keeps its
 * runner-up in `top_candidate` for auditing, but the headline stays UNKNOWN so
 * a below-threshold guess is never read as a classification.
 */
export function predictionLabel(prediction: TrafficPrediction): string {
  return prediction.abstained ? 'UNKNOWN' : prediction.prediction
}

export function predictionSubtitle(prediction: TrafficPrediction): string {
  if (!prediction.abstained) return 'predicted'
  if (prediction.top_candidate) {
    return `abstained · top candidate ${prediction.top_candidate}`
  }
  return 'abstained'
}

/** The four mutually exclusive states that gate the whole Traffic Intelligence view. */
export type MLGateState = 'disabled' | 'no-model' | 'no-data' | 'ready'

/**
 * Reduce health + dataset facts to the one state the page should render. Only
 * `ready` unlocks the prediction views; every other state is an explained
 * empty state rather than a spinner or an error.
 */
export function mlGateState(health: MLHealth | undefined, dataset: MLDatasetReport | undefined): MLGateState {
  if (!health) return 'no-model'
  if (!health.ml_enabled) return 'disabled'
  if (!health.any_model_available) return 'no-model'
  if (dataset && dataset.labeled_rows === 0) return 'no-model'
  return 'ready'
}

/**
 * The backend's own remediation sentence is preferred; this is the fallback for
 * a detail block that carries only a reason.
 */
export function mlRemediation(detail: MLUnavailableDetail | null | undefined): string {
  if (!detail) return ''
  return detail.remediation || 'Train a model with POST /api/v1/ml/train.'
}

/** Label-provenance / rejection-reason counters rendered as `key × value` chips. */
export function counterEntries(counts: Record<string, number>): Array<[string, number]> {
  return Object.entries(counts).sort((a, b) => b[1] - a[1])
}
