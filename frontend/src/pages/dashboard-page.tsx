import {
  BarChart3,
  Database,
  FileText,
  FlaskConical,
  Layers,
  ShieldAlert,
  TriangleAlert,
} from 'lucide-react'

import { StatCard } from '@/components/stat-card'
import { EmptyState } from '@/components/empty-state'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useDashboardStatsQuery, useHealthQuery } from '@/hooks/use-api'
import { ApiClientError } from '@/lib/api-client'

export function DashboardPage() {
  const { data: stats, isPending: statsPending, error: statsError } = useDashboardStatsQuery()
  const { data: health } = useHealthQuery()

  const statsErrorCode =
    statsError instanceof ApiClientError ? statsError.code : 'UNREACHABLE_BACKEND'

  return (
    <div className="mx-auto max-w-7xl space-y-8">
      <section className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground">Overview</h2>
          <p className="text-sm text-muted-foreground">
            Live counters from the backend database. Everything is zero until real data exists.
          </p>
        </div>
        <Badge variant={health?.database === 'connected' ? 'success' : 'danger'}>
          {health ? `API v${health.version} · ${health.database}` : 'API unreachable'}
        </Badge>
      </section>

      {statsError ? (
        <Card className="border-status-danger/40">
          <CardHeader>
            <CardTitle className="text-status-danger">Unable to load dashboard data</CardTitle>
            <CardDescription>
              The backend could not be reached ({statsErrorCode}). Start the backend, then reload.
            </CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <StatCard
            icon={FlaskConical}
            label="Captures"
            value={stats?.captures ?? '—'}
            hint="Uploaded captures"
            tone="info"
          />
          <StatCard
            icon={Layers}
            label="Analysis jobs"
            value={stats?.analysis_jobs ?? '—'}
            hint={`${stats?.pending_jobs ?? 0} pending`}
            tone="warning"
          />
          <StatCard
            icon={BarChart3}
            label="Analyses"
            value={stats?.analyses ?? '—'}
            hint="Completed analyses"
            tone="info"
          />
          <StatCard
            icon={TriangleAlert}
            label="Security findings"
            value={stats?.security_findings ?? '—'}
            hint="Detected issues"
            tone="danger"
          />
          <StatCard
            icon={FileText}
            label="Reports"
            value={stats?.reports ?? '—'}
            hint="Generated reports"
            tone="success"
          />
          <StatCard
            icon={Database}
            label="Pending jobs"
            value={stats?.pending_jobs ?? '—'}
            hint="Queued or running"
            tone="info"
          />
        </section>
      )}

      <section>
        {statsPending && !stats ? null : (
          <EmptyState
            icon={ShieldAlert}
            title="No data yet"
            description="IPsec Sentinel has no captures in its database. Uploading, analysis, and reporting arrive in later phases — the dashboard will populate from real records when that data exists."
          />
        )}
      </section>
    </div>
  )
}