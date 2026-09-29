import { useState } from 'react'
import type { ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  Activity,
  ArrowLeft,
  BarChart3,
  Boxes,
  BrainCircuit,
  Download,
  FileCog,
  FlaskConical,
  Gauge,
  Layers,
  Loader2,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from 'lucide-react'

import { EmptyState } from '@/components/empty-state'
import { ErrorCard, LoadingCard } from '@/components/feedback'
import {
  MLPredictionStats,
  MLPredictionsTable,
  MLStateCard,
  MLUnavailableCard,
} from '@/components/ml-predictions'
import { SecurityFindingsTable, SeverityStat } from '@/components/security-findings'
import { StatusBadge } from '@/components/status-badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { ApiClientError, apiClient } from '@/lib/api-client'
import {
  useAhPacketsQuery,
  useAnalysisQuery,
  useAssessMutation,
  useDeletePredictionsMutation,
  useEspPacketsQuery,
  useFindingsQuery,
  useFlowFeaturesQuery,
  useFlowsQuery,
  useIkeMessagesQuery,
  useMLHealthQuery,
  useMLPredictionsQuery,
  useProtocolObservationsQuery,
  useRunPredictionMutation,
} from '@/hooks/use-api'
import { countBySeverity } from '@/lib/findings'
import { formatConfidence, mlStatusExplanation } from '@/lib/ml'
import {
  formatBytes,
  formatDateTime,
  formatDuration,
  truncateMiddle,
} from '@/lib/utils'
import type { AhPacket, EspPacket, Flow, FlowFeatures, IkeMessage, SecurityFinding } from '@/types/api'

const JOB_REFRESH = 2000

const TABS = [
  { id: 'overview', label: 'Overview', icon: Gauge },
  { id: 'protocol', label: 'Protocol', icon: Layers },
  { id: 'ike', label: 'IKE', icon: Activity },
  { id: 'esp', label: 'ESP', icon: Boxes },
  { id: 'packets', label: 'Packets', icon: BarChart3 },
  { id: 'flows', label: 'Flows', icon: ArrowLeft },
  { id: 'features', label: 'Features', icon: FileCog },
  { id: 'security', label: 'Security', icon: ShieldCheck },
  { id: 'ml', label: 'ML', icon: BrainCircuit },
] as const

type TabId = (typeof TABS)[number]['id']

export function AnalysisDetailPage() {
  const { analysisKey } = useParams<{ analysisKey: string }>()
  const [tab, setTab] = useState<TabId>('overview')
  const { data, isPending, isError } = useAnalysisQuery(analysisKey, JOB_REFRESH)

  const running =
    data?.job?.status === 'running' || data?.job?.status === 'queued' || data?.analysis.status === 'running'

  if (isPending) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center gap-3 py-12 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading analysis…
        </CardContent>
      </Card>
    )
  }

  if (isError || !data) {
    return (
      <Card className="border-status-danger/40">
        <CardHeader>
          <CardTitle className="text-status-danger">Analysis not found</CardTitle>
          <CardDescription>
            <Link to="/analysis" className="inline-flex items-center gap-1.5 text-foreground hover:underline">
              <ArrowLeft className="h-3.5 w-3.5" /> Back to analyses
            </Link>
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  const { analysis } = data

  return (
    <div className="space-y-6">
      <section className="flex items-center gap-3">
        <Link to="/analysis">
          <Button variant="outline" size="sm">
            <ArrowLeft className="h-3.5 w-3.5" /> Back
          </Button>
        </Link>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h2 className="truncate text-xl font-bold tracking-tight text-foreground">
              {analysis.analysis_id ?? analysis.id}
            </h2>
            <StatusBadge value={analysis.status} />
          </div>
          <p className="text-sm text-muted-foreground">
            Capture {analysis.capture_id.slice(0, 8)}… · parser v{analysis.parser_version ?? '—'}
          </p>
        </div>
        <div className="ml-auto">
          {running ? (
            <div className="flex items-center gap-2 text-sm text-status-warning">
              <Loader2 className="h-4 w-4 animate-spin" />
              {data.job?.stage_message ?? 'Working…'} ({Math.round((data.job?.progress ?? 0) * 100)}%)
            </div>
          ) : (
            <div className="flex gap-2">
              <ExportButton href={apiClient.exportUrl(analysisKey as string, 'flows')} label="Flows CSV" />
              <ExportButton href={apiClient.exportUrl(analysisKey as string, 'ike')} label="IKE CSV" />
              <ExportButton href={apiClient.exportUrl(analysisKey as string, 'esp')} label="ESP CSV" />
              <ExportButton href={apiClient.exportUrl(analysisKey as string, 'features')} label="Features JSON" />
            </div>
          )}
        </div>
      </section>

      <div className="flex gap-1 overflow-x-auto rounded-md border border-border bg-card p-1">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={cn(
              'flex items-center gap-1.5 whitespace-nowrap rounded px-3 py-1.5 text-sm font-medium transition-colors',
              tab === id
                ? 'bg-primary text-primary-foreground'
                : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      <TabContent tab={tab} analysisKey={analysisKey as string} summary={data} />

      {analysis.error_message ? (
        <Card className="border-status-danger/40">
          <CardHeader>
            <CardTitle className="text-status-danger">Analysis error</CardTitle>
            <CardDescription>{analysis.error_message}</CardDescription>
          </CardHeader>
        </Card>
      ) : null}
    </div>
  )
}

function ExportButton({ href, label }: { href: string; label: string }) {
  return (
    <a href={href}>
      <Button variant="outline" size="sm">
        <Download className="h-3.5 w-3.5" /> {label}
      </Button>
    </a>
  )
}

function TabContent({
  tab,
  analysisKey,
  summary,
}: {
  tab: TabId
  analysisKey: string
  summary: NonNullable<ReturnType<typeof useAnalysisQuery>['data']>
}) {
  switch (tab) {
    case 'overview':
      return <OverviewTab summary={summary} />
    case 'protocol':
      return <ProtocolTab analysisKey={analysisKey} />
    case 'ike':
      return <IkeTab analysisKey={analysisKey} />
    case 'esp':
      return <EspTab analysisKey={analysisKey} />
    case 'packets':
      return <AhTab analysisKey={analysisKey} />
    case 'flows':
      return <FlowsTab analysisKey={analysisKey} />
    case 'features':
      return <FeaturesTab analysisKey={analysisKey} />
    case 'security':
      return <SecurityTab analysisKey={analysisKey} summary={summary} />
    case 'ml':
      return <MLTab analysisKey={analysisKey} />
  }
}

function OverviewTab({ summary }: { summary: NonNullable<ReturnType<typeof useAnalysisQuery>['data']> }) {
  const a = summary.analysis
  const rows: Array<[string, string | number | null | undefined]> = [
    ['Capture', a.capture_id],
    ['Status', a.status],
    ['IPsec detected', a.protocol_detected],
    ['Confidence', a.protocol_confidence],
    ['IKE detected', a.ike_detected === null ? '—' : a.ike_detected ? 'yes' : 'no'],
    ['ESP detected', a.esp_detected === null ? '—' : a.esp_detected ? 'yes' : 'no'],
    ['AH detected', a.ah_detected === null ? '—' : a.ah_detected ? 'yes' : 'no'],
    ['IPv4 detected', a.ipv4_detected === null ? '—' : a.ipv4_detected ? 'yes' : 'no'],
    ['IPv6 detected', a.ipv6_detected === null ? '—' : a.ipv6_detected ? 'yes' : 'no'],
    ['Packet count', a.packet_count],
    ['Byte count', a.byte_count !== null ? formatBytes(a.byte_count) : '—'],
    ['Duration', formatDuration(a.duration)],
    ['IKE messages', summary.ike_message_count],
    ['ESP packets', summary.esp_packet_count],
    ['AH packets', summary.ah_packet_count],
    ['Flows', summary.flow_count],
    ['Analyzer', a.analyzer_version],
    ['Parser', a.parser_version],
    ['Started', formatDateTime(a.started_at)],
    ['Completed', formatDateTime(a.completed_at)],
  ]
  return (
    <Card>
      <CardHeader>
        <CardTitle>Summary</CardTitle>
        <CardDescription>
          Real results derived from the parsed capture. Unknown values stay unknown — nothing is
          fabricated.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
          {rows.map(([label, value]) => (
            <div key={label} className="space-y-0.5">
              <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
              <dd className="font-mono text-xs text-foreground">
                {value === null || value === undefined ? '—' : String(value)}
              </dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  )
}



function ProtocolTab({ analysisKey }: { analysisKey: string }) {
  const { data, isPending, isError } = useProtocolObservationsQuery(analysisKey)
  if (isPending) return <LoadingCard />
  if (isError || !data) return <ErrorCard message="Protocol observations could not be loaded." />
  const rows = data.items
  if (rows.length === 0) return <EmptyTable title="No protocol observations" />
  return (
    <Card>
      <CardHeader>
        <CardTitle>Protocol observations</CardTitle>
        <CardDescription>Traffic detected across the capture, per protocol.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {rows.map((obs) => (
          <div key={obs.id} className="flex items-center justify-between gap-4 rounded-md border border-border bg-secondary/30 px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 items-center justify-center rounded-md border border-border bg-secondary/40">
                <Layers className="h-4 w-4 text-muted-foreground" />
              </div>
              <div>
                <p className="font-mono text-sm font-medium text-foreground">{obs.protocol}</p>
                <p className="text-xs text-muted-foreground">
                  first {formatDateTime(obs.first_seen)}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <p className="text-sm font-medium text-foreground">{obs.packet_count} packets</p>
                <p className="text-xs text-muted-foreground">{formatBytes(obs.byte_count)}</p>
              </div>
              <StatusBadge value={obs.confidence} kind="confidence" />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

function IkeTab({ analysisKey }: { analysisKey: string }) {
  const { data, isPending, isError } = useIkeMessagesQuery(analysisKey)
  if (isPending) return <LoadingCard />
  if (isError || !data) return <ErrorCard message="IKE messages could not be loaded." />
  const rows = data.items
  if (rows.length === 0) return <EmptyTable title="No IKE messages" />
  return (
    <div className="space-y-4">
      {rows.map((msg) => (
        <IkeMessageCard key={msg.id} message={msg} />
      ))}
    </div>
  )
}

function IkeMessageCard({ message }: { message: IkeMessage }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <CardTitle className="text-sm">{message.exchange_name}</CardTitle>
            <StatusBadge value={message.version} />
            <BadgeOutline>{message.direction}</BadgeOutline>
          </div>
          <p className="text-xs text-muted-foreground">
            #{message.packet_id} · {formatDateTime(message.timestamp)} · SPI{' '}
            <code className="font-mono">{truncateMiddle(message.initiator_spi, 6, 6)}</code>
          </p>
        </div>
        <CardDescription>
          {message.source_ip}:{message.source_port} → {message.destination_ip}:{message.destination_port} ·{' '}
          {message.payload_types.join(', ') || 'no payload types'}
        </CardDescription>
      </CardHeader>
      {message.proposals.length > 0 ? (
        <CardContent className="space-y-2 pt-0">
          {message.proposals.map((p) => (
            <div
              key={p.id}
              className="grid grid-cols-2 gap-3 rounded-md border border-border bg-secondary/30 px-4 py-3 text-xs sm:grid-cols-4"
            >
              <div>
                <p className="text-muted-foreground">Encryption</p>
                <p className="font-mono text-foreground">
                  {p.encryption}
                  {p.key_length ? ` (${p.key_length})` : ''}
                </p>
              </div>
              <div>
                <p className="text-muted-foreground">Integrity</p>
                <p className="font-mono text-foreground">{p.integrity}</p>
              </div>
              <div>
                <p className="text-muted-foreground">PRF</p>
                <p className="font-mono text-foreground">{p.prf}</p>
              </div>
              <div>
                <p className="text-muted-foreground">DH group</p>
                <p className="font-mono text-foreground">{p.dh_group ?? '—'}</p>
              </div>
              <div className="col-span-2 sm:col-span-4">
                <StatusBadge value={p.status} />
              </div>
            </div>
          ))}
        </CardContent>
      ) : null}
    </Card>
  )
}

function BadgeOutline({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center rounded-full border border-border px-2 py-0.5 text-xs font-medium text-muted-foreground">
      {children}
    </span>
  )
}

function EspTab({ analysisKey }: { analysisKey: string }) {
  const { data, isPending, isError } = useEspPacketsQuery(analysisKey)
  if (isPending) return <LoadingCard />
  if (isError || !data) return <ErrorCard message="ESP packets could not be loaded." />
  const rows = data.items
  if (rows.length === 0) return <EmptyTable title="No ESP packets" />
  return (
    <Card>
      <CardHeader>
        <CardTitle>ESP packets</CardTitle>
        <CardDescription>Encapsulating Security Payload records. Decryption is never attempted —
          algorithms are reported as detected or unknown.</CardDescription>
      </CardHeader>
      <CardContent className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
              <th className="py-2 pr-4 font-medium">#</th>
              <th className="py-2 pr-4 font-medium">SPI</th>
              <th className="py-2 pr-4 font-medium">Source</th>
              <th className="py-2 pr-4 font-medium">Dest</th>
              <th className="py-2 pr-4 font-medium">Seq</th>
              <th className="py-2 pr-4 font-medium">Len</th>
              <th className="py-2 pr-4 font-medium">Encryption</th>
              <th className="py-2 text-right font-medium">Dir</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rows.map((pkt) => <EspRow key={pkt.id} pkt={pkt} />)}
          </tbody>
        </table>
      </CardContent>
    </Card>
  )
}

function EspRow({ pkt }: { pkt: EspPacket }) {
  return (
    <tr className="hover:bg-secondary/30">
      <td className="py-2 pr-4 font-mono text-muted-foreground">{pkt.packet_id}</td>
      <td className="py-2 pr-4 font-mono text-foreground">{truncateMiddle(pkt.spi, 6, 4)}</td>
      <td className="py-2 pr-4 font-mono text-foreground">{pkt.source_ip}</td>
      <td className="py-2 pr-4 font-mono text-foreground">{pkt.destination_ip}</td>
      <td className="py-2 pr-4 text-muted-foreground">{pkt.sequence_number ?? '—'}</td>
      <td className="py-2 pr-4 text-muted-foreground">{pkt.length}</td>
      <td className="py-2 pr-4">
        <StatusBadge value={pkt.encryption_algorithm} />
      </td>
      <td className="py-2 text-right text-muted-foreground">{pkt.direction}</td>
    </tr>
  )
}

function AhTab({ analysisKey }: { analysisKey: string }) {
  const { data, isPending, isError } = useAhPacketsQuery(analysisKey)
  if (isPending) return <LoadingCard />
  if (isError || !data) return <ErrorCard message="AH packets could not be loaded." />
  const rows: AhPacket[] = data.items
  if (rows.length === 0) return <EmptyTable title="No AH packets" />
  return (
    <Card>
      <CardHeader>
        <CardTitle>AH packets</CardTitle>
        <CardDescription>Authentication Header records. IPsec packets that are neither ESP nor IKE
          are also listed here if recognized.</CardDescription>
      </CardHeader>
      <CardContent className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
              <th className="py-2 pr-4 font-medium">#</th>
              <th className="py-2 pr-4 font-medium">SPI</th>
              <th className="py-2 pr-4 font-medium">Source</th>
              <th className="py-2 pr-4 font-medium">Dest</th>
              <th className="py-2 pr-4 font-medium">Seq</th>
              <th className="py-2 pr-4 font-medium">Next header</th>
              <th className="py-2 text-right font-medium">Dir</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rows.map((pkt) => (
              <tr key={pkt.id} className="hover:bg-secondary/30">
                <td className="py-2 pr-4 font-mono text-muted-foreground">{pkt.packet_id}</td>
                <td className="py-2 pr-4 font-mono text-foreground">{truncateMiddle(pkt.spi, 6, 4)}</td>
                <td className="py-2 pr-4 font-mono text-foreground">{pkt.source_ip}</td>
                <td className="py-2 pr-4 font-mono text-foreground">{pkt.destination_ip}</td>
                <td className="py-2 pr-4 text-muted-foreground">{pkt.sequence_number ?? '—'}</td>
                <td className="py-2 pr-4 text-muted-foreground">{pkt.next_header ?? '—'}</td>
                <td className="py-2 text-right text-muted-foreground">{pkt.direction}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  )
}

function FlowsTab({ analysisKey }: { analysisKey: string }) {
  const { data, isPending, isError } = useFlowsQuery(analysisKey)
  if (isPending) return <LoadingCard />
  if (isError || !data) return <ErrorCard message="Flows could not be loaded." />
  const rows: Flow[] = data.items
  if (rows.length === 0) return <EmptyTable title="No flows" />
  return (
    <Card>
      <CardHeader>
        <CardTitle>Flows</CardTitle>
        <CardDescription>Bidirectional flows derived from matched endpoints and protocols.</CardDescription>
      </CardHeader>
      <CardContent className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
              <th className="py-2 pr-4 font-medium">Flow</th>
              <th className="py-2 pr-4 font-medium">Stream</th>
              <th className="py-2 pr-4 font-medium">Packets</th>
              <th className="py-2 pr-4 font-medium">Bytes</th>
              <th className="py-2 pr-4 font-medium">Duration</th>
              <th className="py-2 pr-4 font-medium">IKE/ESP/AH</th>
              <th className="py-2 text-right font-medium">Direction</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rows.map((flow) => (
              <tr key={flow.id} className="hover:bg-secondary/30">
                <td className="py-2 pr-4 font-mono text-foreground">{flow.flow_id}</td>
                <td className="py-2 pr-4 font-mono text-muted-foreground">
                  {flow.source_ip}:{flow.source_port ?? '—'} → {flow.destination_ip}:
                  {flow.destination_port ?? '—'} ({flow.protocol})
                </td>
                <td className="py-2 pr-4 text-muted-foreground">{flow.packet_count}</td>
                <td className="py-2 pr-4 text-muted-foreground">{formatBytes(flow.byte_count)}</td>
                <td className="py-2 pr-4 text-muted-foreground">{formatDuration(flow.duration)}</td>
                <td className="py-2 pr-4 text-muted-foreground">
                  {flow.ike_packets}/{flow.esp_packets}/{flow.ah_packets}
                </td>
                <td className="py-2 text-right">
                  <StatusBadge value={flow.direction} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  )
}

function FeaturesTab({ analysisKey }: { analysisKey: string }) {
  const { data, isPending, isError } = useFlowFeaturesQuery(analysisKey)
  if (isPending) return <LoadingCard />
  if (isError || !data) return <ErrorCard message="Flow features could not be loaded." />
  const rows: FlowFeatures[] = data.items
  if (rows.length === 0) return <EmptyTable title="No flow features" />
  return (
    <div className="space-y-4">
      {rows.map((feature) => (
        <Card key={feature.id}>
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="text-sm">Flow {feature.flow_key ?? feature.flow_id}</CardTitle>
              <span className="text-xs text-muted-foreground">
                schema {feature.feature_schema_version}
              </span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4 lg:grid-cols-6">
              {Object.entries(feature.features)
                .filter(([key]) => !key.includes('histogram'))
                .map(([key, value]) => (
                  <div key={key} className="rounded-md border border-border bg-secondary/30 px-3 py-2">
                    <p className="truncate text-muted-foreground">{key}</p>
                    <p className="font-mono text-foreground">{renderFeatureValue(value)}</p>
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function renderFeatureValue(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'number') {
    if (Number.isInteger(value)) return String(value)
    return value.toFixed(4)
  }
  if (Array.isArray(value)) return `[${value.length} entries]`
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function SecurityTab({
  analysisKey,
  summary,
}: {
  analysisKey: string
  summary: NonNullable<ReturnType<typeof useAnalysisQuery>['data']>
}) {
  const { data, isPending, isError } = useFindingsQuery(analysisKey)
  const assess = useAssessMutation()
  const analysis = summary.analysis
  const notAssessable = analysis.status !== 'completed' || summary.job?.status === 'running'

  const rows: SecurityFinding[] = data?.items ?? []
  const counts = countBySeverity(rows)

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle>Security assessment</CardTitle>
              <CardDescription>
                Deterministic rules evaluated against the persisted analysis data (never the raw
                capture). No decryption, no model predictions — findings are reproducible with
                evidence.
              </CardDescription>
            </div>
            <div className="flex flex-col items-end gap-1">
              <Button
                onClick={() => assess.mutate(analysisKey)}
                disabled={notAssessable || assess.isPending}
              >
                {assess.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <RefreshCw className="h-3.5 w-3.5" />
                )}
                {analysis.rule_version ? 'Re-run assessment' : 'Run assessment'}
              </Button>
              <p className="text-xs text-muted-foreground">
                {analysis.rule_version ? (
                  <>rules v{analysis.rule_version} · last assessed</>
                ) : notAssessable ? (
                  'requires a completed analysis'
                ) : (
                  'not assessed yet'
                )}
              </p>
            </div>
          </div>
        </CardHeader>
        {assess.isError ? (
          <CardContent>
            <ErrorCard message={(assess.error as Error).message} />
          </CardContent>
        ) : null}
        {assess.data ? (
          <CardContent>
            <div className="rounded-md border border-border bg-secondary/30 px-4 py-3 text-sm">
              Assessment complete in {assess.data.duration_ms} ms: {assess.data.rules_run} rules run,{' '}
              {assess.data.created} finding(s) created, {assess.data.skipped} rule(s) skipped
              (idempotent re-run). New rules version v{assess.data.rule_version}.
            </div>
          </CardContent>
        ) : null}
      </Card>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <SeverityStat label="Total" value={counts.total} />
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
        <EmptyTable title="No security findings" />
      ) : (
        <SecurityFindingsTable rows={rows} />
      )}
    </div>
  )
}






/**
 * Phase 4 ML section.
 *
 * Deliberately read-mostly: this tab shows the stored predictions for one
 * analysis and can trigger an inference run, but it never trains, never edits
 * labels, and never writes a finding. The honest "nothing here" states — ML
 * disabled, no model registered, and no flow features — are each rendered as an
 * explained panel rather than an empty table or a failure banner, because in
 * this repository all three are the expected state.
 */
function MLTab({ analysisKey }: { analysisKey: string }) {
  const health = useMLHealthQuery()
  const run = useRunPredictionMutation()
  const clear = useDeletePredictionsMutation()
  const predictions = useMLPredictionsQuery(analysisKey)

  const mlEnabled = health.data?.ml_enabled ?? false
  const modelVersion = health.data?.active_model_version ?? null
  const runResult = run.data
  const rows = predictions.data?.predictions ?? []
  const canRun = mlEnabled && modelVersion !== null && health.data?.any_model_available === true

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle className="flex items-center gap-2">
                <BrainCircuit className="h-4 w-4 text-brand" /> Traffic classification
              </CardTitle>
              <CardDescription>
                Supervised flow labels from the Phase 4 model. These are informational only: they
                do not create findings and do not alter risk level or security score.
              </CardDescription>
            </div>
            <div className="flex flex-col items-end gap-1">
              <div className="flex gap-2">
                <Button
                  size="sm"
                  onClick={() => run.mutate({ analysisKey, modelVersion: modelVersion ?? undefined })}
                  disabled={!canRun || run.isPending}
                >
                  {run.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <RefreshCw className="h-3.5 w-3.5" />
                  )}
                  Run inference
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => clear.mutate(analysisKey)}
                  disabled={clear.isPending || rows.length === 0}
                >
                  {clear.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Trash2 className="h-3.5 w-3.5" />
                  )}
                  Clear
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                {modelVersion
                  ? `Model ${modelVersion} · threshold ${formatConfidence(health.data?.min_confidence ?? null)}`
                  : 'No compatible model is registered'}
              </p>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {run.isError ? (
            <ErrorCard
              message={
                run.error instanceof ApiClientError
                  ? `${run.error.message} (${run.error.code})`
                  : 'Inference failed.'
              }
            />
          ) : null}
          {runResult ? (
            <div className="space-y-1.5 rounded-md border border-border bg-secondary/30 px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge value={runResult.status} kind="ml" />
                <span className="text-sm text-foreground">
                  {runResult.created} created · {runResult.updated} updated · {runResult.rejected}{' '}
                  rejected of {runResult.total} flows
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                {mlStatusExplanation(runResult.status)}
              </p>
              <p className="text-xs text-muted-foreground">
                Stored as <span className="font-mono">{runResult.observation_status}</span>{' '}
                observations. Re-running updates rows in place.
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

      {!mlEnabled ? (
        <MLStateCard
          status="DISABLED"
          title="Traffic classification is disabled"
          action={
            <p className="text-xs text-muted-foreground">
              Set <span className="font-mono">ML_ENABLED=true</span> on the backend to enable
              inference for this analysis.
            </p>
          }
        />
      ) : null}

      {mlEnabled && !modelVersion ? (
        <MLUnavailableCard status="MODEL_NOT_AVAILABLE" detail={health.data?.detail ?? null} />
      ) : null}

      {predictions.data?.status === 'INSUFFICIENT_DATA' ? (
        <MLStateCard
          status="INSUFFICIENT_DATA"
          title="No flow features to score"
          action={
            <p className="text-xs text-muted-foreground">
              This analysis produced no flow features, so there is nothing for a model to classify.
            </p>
          }
        />
      ) : null}

      {predictions.isPending ? <LoadingCard /> : null}
      {predictions.isError ? (
        <ErrorCard message="Stored ML predictions could not be loaded." />
      ) : null}

      {rows.length > 0 ? (
        <>
          <MLPredictionStats summary={predictions.data?.summary ?? FALLBACK_SUMMARY} />
          <MLPredictionsTable rows={rows} />
        </>
      ) : null}

      {mlEnabled &&
      modelVersion &&
      rows.length === 0 &&
      !predictions.isPending &&
      !predictions.isError &&
      predictions.data?.status !== 'INSUFFICIENT_DATA' ? (
        <EmptyState
          icon={BrainCircuit}
          title="No predictions for this analysis"
          description="Nothing has been scored yet. Running inference classifies this analysis's flows using the active model and stores the results here."
          action={
            <p className="text-xs text-muted-foreground">
              Training happens on the server and requires ground-truth labels supplied by an
              operator. This project ships no pre-trained model.
            </p>
          }
        />
      ) : null}
    </div>
  )
}

const FALLBACK_SUMMARY = {
  count: 0,
  model_version: null,
  average_confidence: null,
  unknown_count: 0,
  abstained_count: 0,
  low_confidence_count: 0,
  class_distribution: {},
}

function EmptyTable({ title }: { title: string }) {
  return (
    <EmptyState
      icon={FlaskConical}
      title={title}
      description="No data is available for this analysis."
    />
  )
}