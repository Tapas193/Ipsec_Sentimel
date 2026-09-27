import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, FileSearch, Loader2, Play } from 'lucide-react'

import { StatusBadge } from '@/components/status-badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useAnalyzeCaptureMutation, useCaptureQuery } from '@/hooks/use-api'
import { formatBytes, formatDateTime } from '@/lib/utils'
import type { Capture } from '@/types/api'

export function CaptureDetailPage() {
  const { captureKey } = useParams<{ captureKey: string }>()
  const { data, isPending, isError } = useCaptureQuery(captureKey)
  const analyze = useAnalyzeCaptureMutation()

  if (isPending) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center gap-3 py-12 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading capture…
        </CardContent>
      </Card>
    )
  }

  if (isError || !data) {
    return (
      <Card className="border-status-danger/40">
        <CardHeader>
          <CardTitle className="text-status-danger">Capture not found</CardTitle>
          <CardDescription>
            <Link to="/captures" className="inline-flex items-center gap-1.5 text-foreground hover:underline">
              <ArrowLeft className="h-3.5 w-3.5" /> Back to captures
            </Link>
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      <section className="flex items-center gap-3">
        <Link to="/captures">
          <Button variant="outline" size="sm">
            <ArrowLeft className="h-3.5 w-3.5" /> Back
          </Button>
        </Link>
        <div className="min-w-0">
          <h2 className="truncate text-xl font-bold tracking-tight text-foreground">
            {data.original_filename}
          </h2>
          <p className="text-sm text-muted-foreground">
            {data.capture_id ?? data.capture_reference} ·{' '}
            {data.capture_format?.toUpperCase() ?? 'unknown'}
          </p>
        </div>
        <div className="ml-auto">
          <StatusBadge value={data.status} />
        </div>
      </section>

      <CaptureMeta capture={data} />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileSearch className="h-4 w-4 text-brand" /> Analyze
          </CardTitle>
          <CardDescription>
            Run IPsec packet analysis on this capture. IKE/ESP/AH messages, flows and features are
            derived from real parsed packets.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            disabled={analyze.isPending || data.status === 'invalid'}
            onClick={() => data.capture_id && analyze.mutate(data.capture_id)}
          >
            {analyze.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Play className="h-4 w-4" />
            )}
            {analyze.isPending ? 'Starting analysis…' : 'Run analysis'}
          </Button>
          {analyze.isError ? (
            <p className="mt-3 text-sm text-status-danger">
              {analyze.error instanceof Error ? analyze.error.message : 'Analysis failed to start'}
            </p>
          ) : null}
          {analyze.isSuccess ? (
            <p className="mt-3 text-sm text-status-success">
              Analysis started.{' '}
              <Link
                to={`/analysis/${analyze.data.analysis_id}`}
                className="font-medium underline"
              >
                View job {analyze.data.analysis_reference}
              </Link>
            </p>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}

function captureDetails(c: Capture): Array<[string, string]> {
  return [
    ['Filename', c.original_filename],
    ['Stored as', c.stored_filename ?? c.filename],
    ['File size', formatBytes(c.file_size)],
    ['SHA-256', c.sha256],
    ['Format', c.capture_format?.toUpperCase() ?? 'unknown'],
    ['Packet count', c.packet_count !== null ? String(c.packet_count) : '—'],
    ['Duration', c.duration !== null ? `${c.duration.toFixed(3)} s` : '—'],
    ['Uploaded', formatDateTime(c.uploaded_at)],
    ['First packet', formatDateTime(c.first_packet_time)],
    ['Last packet', formatDateTime(c.last_packet_time)],
    ['Analysis status', c.analysis_status ?? '—'],
  ]
}

function CaptureMeta({ capture }: { capture: Capture }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Capture details</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
          {captureDetails(capture).map(([label, value]) => (
            <div key={label} className="space-y-0.5">
              <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
              <dd className="break-all font-mono text-xs text-foreground">{value}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  )
}