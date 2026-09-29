import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'

import { EmptyState } from '@/components/empty-state'
import { ErrorCard, LoadingCard } from '@/components/feedback'
import { SecurityFindingsTable, SeverityStat } from '@/components/security-findings'
import { Button } from '@/components/ui/button'
import { useAllFindingsQuery } from '@/hooks/use-api'
import { countBySeverity } from '@/lib/findings'

/**
 * Cross-analysis findings view. Phase 3 rules are implemented and the backend
 * serves GET /findings, so this lists real persisted findings rather than
 * claiming detection is unavailable.
 */
export function FindingsPage() {
  const [page, setPage] = useState(1)
  const { data, isPending, isError } = useAllFindingsQuery(page)

  const rows = data?.items ?? []
  const counts = countBySeverity(rows)
  const pagination = data?.pagination
  const total = pagination?.total ?? 0

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <SeverityStat label="Total" value={total} />
        <SeverityStat label="Critical" value={counts.CRITICAL} variant="danger" />
        <SeverityStat label="High" value={counts.HIGH} variant="danger" />
        <SeverityStat label="Medium" value={counts.MEDIUM} variant="warning" />
        <SeverityStat label="Low" value={counts.LOW} variant="info" />
        <SeverityStat label="Info" value={counts.INFO} variant="secondary" />
      </div>

      {isPending ? (
        <LoadingCard />
      ) : isError ? (
        <ErrorCard message="Security findings could not be loaded." />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="No security findings"
          description="No capture has triggered a detection rule yet. Upload a PCAP and run an analysis to produce findings."
        />
      ) : (
        <>
          <SecurityFindingsTable rows={rows} />
          {pagination && pagination.total_pages > 1 ? (
            <div className="flex items-center justify-between gap-3 text-sm">
              <p className="text-muted-foreground">
                Page {pagination.page} of {pagination.total_pages} · {total} findings
              </p>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1 || isPending}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= pagination.total_pages || isPending}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          ) : null}
          <p className="text-xs text-muted-foreground">
            Findings are produced by deterministic Phase 3 rules — no model predictions. Open an{' '}
            <Link to="/analysis" className="underline underline-offset-4">
              analysis
            </Link>{' '}
            to inspect the evidence for a specific capture.
          </p>
        </>
      )}
    </div>
  )
}
