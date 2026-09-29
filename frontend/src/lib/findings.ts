import type { SecurityFinding } from '@/types/api'

/**
 * Severity levels emitted by the backend `Severity` enum
 * (backend/app/models/finding.py), uppercased for use as object keys.
 */
export const SEVERITY_KEYS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

export type SeverityKey = (typeof SEVERITY_KEYS)[number]

export interface SeverityCounts {
  total: number
  CRITICAL: number
  HIGH: number
  MEDIUM: number
  LOW: number
  INFO: number
}

/**
 * Count findings per severity. Kept out of the components so the per-analysis
 * Security tab and the global Findings page share one roll-up implementation,
 * and so component modules only export components.
 */
export function countBySeverity(rows: SecurityFinding[]): SeverityCounts {
  const counts: SeverityCounts = {
    total: rows.length,
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  }
  for (const finding of rows) {
    const key = (finding.severity ?? 'INFO').toUpperCase()
    if (key in counts && key !== 'total') counts[key as SeverityKey] += 1
  }
  return counts
}
