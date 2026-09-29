import { Badge } from '@/components/ui/badge'
import { mlStatusTone } from '@/lib/ml'

type Tone = 'success' | 'warning' | 'danger' | 'info' | 'secondary'

/**
 * Tone maps are partitioned by semantic domain, not merged into one global
 * lookup. Severity and confidence intentionally share vocabulary (`high`,
 * `medium`, `low`) while meaning opposite things: a HIGH severity is dangerous,
 * a HIGH confidence is reassuring. Keeping them in separate maps is what stops a
 * HIGH finding from rendering green, and stops HIGH confidence from rendering
 * red. A new domain gets its own map and an explicit `kind` instead of silently
 * reusing another domain's tones.
 */

/** Capture / analysis / finding lifecycle. Operational states only. */
const TONE_BY_STATUS: Record<string, Tone> = {
  uploaded: 'secondary',
  queued: 'secondary',
  analyzing_pending: 'secondary',
  analyzing: 'warning',
  running: 'warning',
  partial: 'warning',
  valid: 'success',
  analyzed: 'success',
  completed: 'success',
  failed: 'danger',
  invalid: 'danger',
  // Boolean protocol-detection indicator.
  yes: 'success',
  no: 'danger',
  // Finding lifecycle.
  open: 'secondary',
  acknowledged: 'warning',
  resolved: 'success',
}

/** Backend `Severity` enum (backend/app/models/finding.py). */
const TONE_BY_SEVERITY: Record<string, Tone> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'info',
  info: 'secondary',
  unknown: 'secondary',
}

/** Backend `FindingConfidence` / protocol-observation confidence. */
const TONE_BY_CONFIDENCE: Record<string, Tone> = {
  high: 'success',
  medium: 'warning',
  low: 'info',
  unknown: 'secondary',
}

function toneFor(
  value: string,
  kind: 'status' | 'severity' | 'confidence' | 'ml',
): Tone {
  const key = value.toLowerCase()
  if (kind === 'severity') return TONE_BY_SEVERITY[key] ?? 'secondary'
  if (kind === 'confidence') return TONE_BY_CONFIDENCE[key] ?? 'secondary'
  // ML statuses are SCREAMING_SNAKE and already have their own partition in
  // `lib/ml`, so they are routed there rather than through the lowercase maps.
  if (kind === 'ml') return mlStatusTone(value)
  return TONE_BY_STATUS[key] ?? 'secondary'
}

export function StatusBadge({
  value,
  kind = 'status',
}: {
  value: string | null | undefined
  kind?: 'status' | 'severity' | 'confidence' | 'ml'
}) {
  if (!value) {
    return <Badge variant="outline">unknown</Badge>
  }
  return <Badge variant={toneFor(value, kind)}>{value}</Badge>
}
