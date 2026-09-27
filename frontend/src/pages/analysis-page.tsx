import { useState } from 'react'
import { Link } from 'react-router-dom'
import { BarChart3, Loader2 } from 'lucide-react'

import { EmptyState } from '@/components/empty-state'
import { StatusBadge } from '@/components/status-badge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useAnalysesQuery, useJobsQuery } from '@/hooks/use-api'
import { formatDateTime, formatDuration } from '@/lib/utils'
import type { Analysis } from '@/types/api'

const JOB_REFRESH = 3000

export function AnalysisPage() {
  const [page, setPage] = useState(1)
  const { data, isPending, isError } = useAnalysesQuery(page, JOB_REFRESH)
  const { data: jobs } = useJobsQuery(1, JOB_REFRESH)
  const items = data?.items ?? []

  const running = (jobs?.items ?? []).filter((job) => job.status === 'running' || job.status === 'queued')

  return (
    <div className="space-y-6">
      <section className="flex flex-col gap-1.5">
        <h2 className="text-xl font-bold tracking-tight text-foreground">Analysis</h2>
        <p className="text-sm text-muted-foreground">
          Packet analyses run against uploaded captures. Results are derived entirely from real
          parsed packets — no values are fabricated.
        </p>
      </section>

      {running.length > 0 ? <RunningJobs jobs={running} /> : null}

      {isPending ? (
        <Card>
          <CardContent className="flex items-center justify-center gap-3 py-12 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading analyses…
          </CardContent>
        </Card>
      ) : isError ? (
        <Card className="border-status-danger/40">
          <CardHeader>
            <CardTitle className="text-status-danger">Unable to load analyses</CardTitle>
            <CardDescription>Start the backend, then reload this page.</CardDescription>
          </CardHeader>
        </Card>
      ) : items.length === 0 ? (
        <EmptyState
          icon={BarChart3}
          title="No analyses yet"
          description="Upload a capture and trigger analysis from the Captures page to see results here."
        />
      ) : (
        <AnalysisTable items={items} page={page} setPage={setPage} totalPages={data?.pagination.total_pages ?? 1} />
      )}
    </div>
  )
}

function RunningJobs({ jobs }: { jobs: Array<{ job_id: string | null; current_stage: string | null; progress: number }> }) {
  return (
    <Card className="border-status-warning/40">
      <CardHeader>
        <CardTitle className="text-status-warning">
          {jobs.length} job{jobs.length === 1 ? '' : 's'} in progress
        </CardTitle>
        <CardDescription>This page refreshes automatically while jobs run.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {jobs.map((job, index) => (
          <div key={job.job_id ?? `job-${index}`} className="space-y-1">
            <div className="flex items-center justify-between text-sm">
              <span className="font-medium text-foreground">{job.current_stage ?? 'Starting…'}</span>
              <span className="text-muted-foreground">{Math.round(job.progress * 100)}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary">
              <div
                className="h-full rounded-full bg-primary transition-all"
                style={{ width: `${job.progress * 100}%` }}
              />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

function AnalysisTable({
  items,
  page,
  setPage,
  totalPages,
}: {
  items: Analysis[]
  page: number
  setPage: (page: number) => void
  totalPages: number
}) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-4">
          <div>
            <CardTitle>Analysis list</CardTitle>
            <CardDescription>Completed and in-progress packet analyses.</CardDescription>
          </div>
          <Link to="/captures">
            <Button size="sm" variant="outline">
              Upload a capture
            </Button>
          </Link>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
                <th className="py-2 pr-4 font-medium">Analysis</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 font-medium">IPsec</th>
                <th className="py-2 pr-4 font-medium">Packets</th>
                <th className="py-2 pr-4 font-medium">Duration</th>
                <th className="py-2 text-right font-medium">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {items.map((analysis) => {
                const key = analysis.analysis_id ?? analysis.id
                return (
                  <tr key={analysis.id} className="align-middle hover:bg-secondary/30">
                    <td className="py-3 pr-4">
                      <Link
                        to={`/analysis/${key}`}
                        className="font-medium text-foreground hover:underline"
                      >
                        {analysis.analysis_id ?? analysis.id}
                      </Link>
                      {analysis.status === 'running' ? (
                        <Badge variant="warning" className="ml-2">
                          running
                        </Badge>
                      ) : null}
                    </td>
                    <td className="py-3 pr-4">
                      <StatusBadge value={analysis.status} />
                    </td>
                    <td className="py-3 pr-4">
                      {analysis.protocol_detected === 'yes' ? (
                        <Badge variant="success">yes</Badge>
                      ) : (
                        <StatusBadge value={analysis.protocol_detected} />
                      )}
                    </td>
                    <td className="py-3 pr-4 text-muted-foreground">
                      {analysis.packet_count ?? '—'}
                    </td>
                    <td className="py-3 pr-4 text-muted-foreground">
                      {formatDuration(analysis.duration)}
                    </td>
                    <td className="py-3 text-right text-muted-foreground">
                      {formatDateTime(analysis.started_at)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        {totalPages > 1 ? (
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              Page {page} of {totalPages}
            </span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
                Previous
              </Button>
              <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
                Next
              </Button>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  )
}