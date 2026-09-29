import { useState } from 'react'

import { StatusBadge } from '@/components/status-badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { cn, formatDateTime } from '@/lib/utils'
import type { SecurityFinding } from '@/types/api'

/**
 * Severity roll-up shown above a findings table. Kept here so the per-analysis
 * Security tab and the global Findings page cannot drift apart.
 */
export function SeverityStat({
  label,
  value,
  variant = 'secondary',
}: {
  label: string
  /** String values are used when the value is a formatted non-count, e.g. a percentage. */
  value: number | string
  variant?: 'danger' | 'warning' | 'info' | 'secondary'
}) {
  return (
    <Card>
      <CardContent className="flex items-center justify-between gap-3 py-3">
        <span className="text-sm text-muted-foreground">{label}</span>
        <span
          className={cn(
            typeof value === 'number' ? 'text-lg tabular-nums' : 'text-sm',
            'font-bold',
            variant === 'danger' && 'text-status-danger',
            variant === 'warning' && 'text-status-warning',
            variant === 'info' && 'text-status-info',
          )}
        >
          {value}
        </span>
      </CardContent>
    </Card>
  )
}

export function SecurityFindingsTable({ rows }: { rows: SecurityFinding[] }) {
  const [expanded, setExpanded] = useState<string | null>(null)
  return (
    <Card>
      <CardHeader>
        <CardTitle>Findings</CardTitle>
        <CardDescription>
          Deterministic findings with machine-readable evidence. Click a row to inspect the evidence.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {rows.map((finding) => {
          const isOpen = expanded === finding.id
          return (
            <div key={finding.id} className="rounded-md border border-border">
              <button
                type="button"
                onClick={() => setExpanded(isOpen ? null : finding.id)}
                className="flex w-full flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5 text-left hover:bg-secondary/30"
              >
                <span className="font-mono text-xs text-muted-foreground">
                  {finding.finding_id ?? finding.id.slice(0, 8)}
                </span>
                <span className="font-mono text-xs text-muted-foreground">{finding.rule_id}</span>
                <span className="min-w-0 flex-1 truncate text-sm font-medium text-foreground">
                  {finding.title}
                </span>
                <StatusBadge value={finding.severity} kind="severity" />
                <StatusBadge value={finding.confidence} kind="confidence" />
                <StatusBadge value={finding.status} />
              </button>
              {isOpen ? <FindingDetail finding={finding} /> : null}
            </div>
          )
        })}
      </CardContent>
    </Card>
  )
}

function FindingDetail({ finding }: { finding: SecurityFinding }) {
  const evidence = finding.evidence
  const meta: Array<[string, string | number | null | undefined]> = [
    ['Finding ID', finding.finding_id],
    ['Rule ID', finding.rule_id],
    ['Rules version', finding.rule_version],
    ['Category', finding.category],
    ['Type', finding.finding_type],
    ['Source', finding.source],
    ['Created', formatDateTime(finding.created_at)],
  ]
  return (
    <div className="space-y-4 border-t border-border px-4 py-4 text-sm">
      <div className="grid gap-x-8 gap-y-2 sm:grid-cols-2 lg:grid-cols-4">
        {meta.map(([label, value]) => (
          <div key={label} className="space-y-0.5">
            <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
            <dd className="font-mono text-xs text-foreground">{value ?? '—'}</dd>
          </div>
        ))}
      </div>

      {finding.observed_value || finding.expected_value ? (
        <div className="grid gap-3 sm:grid-cols-2">
          <DetailLine label="Observed" value={finding.observed_value} />
          <DetailLine label="Expected" value={finding.expected_value} />
        </div>
      ) : null}

      {finding.description ? <DetailLine label="Description" value={finding.description} /> : null}
      {finding.impact ? <DetailLine label="Impact" value={finding.impact} /> : null}
      {finding.recommendation ? (
        <DetailLine label="Recommendation" value={finding.recommendation} />
      ) : null}

      {evidence ? <EvidenceBlock evidence={evidence} /> : null}
    </div>
  )
}

function DetailLine({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value) return null
  return (
    <div className="rounded-md border border-border bg-secondary/30 px-3 py-2">
      <p className="text-xs uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className="mt-0.5 whitespace-pre-wrap text-foreground">{value}</p>
    </div>
  )
}

export function EvidenceBlock({ evidence }: { evidence: NonNullable<SecurityFinding['evidence']> }) {
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">
        Evidence — schema v{evidence.version}
        {evidence.packet_ids.length > 0 ? ` · packets ${evidence.packet_ids.join(', ')}` : ''}
        {evidence.message_ids.length > 0 ? ` · IKE messages ${evidence.message_ids.join(', ')}` : ''}
      </p>
      {evidence.items.length > 0 ? (
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-border uppercase tracking-wider text-muted-foreground">
                <th className="py-1.5 pl-3 pr-3 font-medium">Source</th>
                <th className="py-1.5 pr-3 font-medium">Field</th>
                <th className="py-1.5 pr-3 font-medium">Observed</th>
                <th className="py-1.5 pr-3 font-medium">Expected</th>
                <th className="py-1.5 pr-3 font-medium">Observation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {evidence.items.map((item, index) => (
                <tr key={index}>
                  <td className="py-1.5 pl-3 pr-3 font-mono text-muted-foreground">{item.source}</td>
                  <td className="py-1.5 pr-3 font-mono text-muted-foreground">{item.field}</td>
                  <td className="py-1.5 pr-3 font-mono text-foreground">{item.observed_value ?? '—'}</td>
                  <td className="py-1.5 pr-3 font-mono text-muted-foreground">
                    {item.expected_value ?? '—'}
                  </td>
                  <td className="py-1.5 pr-3 text-muted-foreground">{item.observation_status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {evidence.notes.length > 0 ? (
        <ul className="list-inside list-disc space-y-1 text-xs text-muted-foreground">
          {evidence.notes.map((note, index) => (
            <li key={index}>{note}</li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}
