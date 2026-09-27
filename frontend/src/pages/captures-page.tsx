import { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { FlaskConical, HardDriveUpload, Loader2, Play, Trash2 } from 'lucide-react'

import { EmptyState } from '@/components/empty-state'
import { StatusBadge } from '@/components/status-badge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  useAnalyzeCaptureMutation,
  useCapturesQuery,
  useDeleteCaptureMutation,
} from '@/hooks/use-api'
import { apiClient } from '@/lib/api-client'
import { formatBytes, formatDateTime, truncateMiddle } from '@/lib/utils'
import type { Capture } from '@/types/api'

export function CapturesPage() {
  const [page, setPage] = useState(1)
  const { data, isPending, isError } = useCapturesQuery(page)
  const items = data?.items ?? []

  return (
    <div className="space-y-6">
      <section className="flex flex-col gap-1.5">
        <h2 className="text-xl font-bold tracking-tight text-foreground">Captures</h2>
        <p className="text-sm text-muted-foreground">
          Uploaded PCAP/PCAPNG files. Upload a capture, then run packet analysis on it.
        </p>
      </section>

      <UploadCard onUploaded={() => setPage(1)} />

      {isPending ? (
        <Card>
          <CardContent className="flex items-center justify-center gap-3 py-12 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading captures…
          </CardContent>
        </Card>
      ) : isError ? (
        <Card className="border-status-danger/40">
          <CardHeader>
            <CardTitle className="text-status-danger">Unable to load captures</CardTitle>
            <CardDescription>Start the backend, then reload this page.</CardDescription>
          </CardHeader>
        </Card>
      ) : items.length === 0 ? (
        <EmptyState
          icon={FlaskConical}
          title="No captures yet"
          description="Upload a PCAP or PCAPNG file above to start analyzing IPsec traffic."
        />
      ) : (
        <CaptureTable items={items} page={page} setPage={setPage} totalPages={data?.pagination.total_pages ?? 1} />
      )}
    </div>
  )
}

function UploadCard({ onUploaded }: { onUploaded: () => void }) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [progress, setProgress] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)

  async function handleFile(file: File | undefined) {
    if (!file) return
    setError(null)
    setProgress(0)
    setUploading(true)
    try {
      await apiClient.uploadCapture(file, setProgress)
      onUploaded()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed')
    } finally {
      setUploading(false)
      setProgress(null)
      if (inputRef.current) inputRef.current.value = ''
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <HardDriveUpload className="h-4 w-4 text-brand" /> Upload capture
        </CardTitle>
        <CardDescription>
          Supports .pcap and .pcapng. Files are validated, hashed (SHA-256) and stored before analysis.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap,.pcapng,application/vnd.tcpdump.pcap,application/x-pcapng"
          className="block w-full cursor-pointer rounded-md border border-border bg-secondary/40 px-3 py-2 text-sm text-foreground file:mr-3 file:rounded-md file:border-0 file:bg-primary file:px-3 file:py-1.5 file:text-sm file:font-medium file:text-primary-foreground disabled:opacity-50"
          disabled={uploading}
          onChange={(event) => void handleFile(event.target.files?.[0])}
        />
        {uploading ? (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Uploading… {progress !== null ? `${progress}%` : ''}
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary">
              <div
                className="h-full rounded-full bg-primary transition-all"
                style={{ width: `${progress ?? 0}%` }}
              />
            </div>
          </div>
        ) : null}
        {error ? <p className="text-sm text-status-danger">{error}</p> : null}
      </CardContent>
    </Card>
  )
}

function CaptureTable({
  items,
  page,
  setPage,
  totalPages,
}: {
  items: Capture[]
  page: number
  setPage: (page: number) => void
  totalPages: number
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Capture list</CardTitle>
        <CardDescription>Recorded captures with validation and analysis state.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase tracking-wider text-muted-foreground">
                <th className="py-2 pr-4 font-medium">Capture</th>
                <th className="py-2 pr-4 font-medium">SHA-256</th>
                <th className="py-2 pr-4 font-medium">Size</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 font-medium">Uploaded</th>
                <th className="py-2 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {items.map((capture) => (
                <CaptureRow key={capture.id} capture={capture} />
              ))}
            </tbody>
          </table>
        </div>
        {totalPages > 1 ? (
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              Page {page} of {totalPages}
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages}
                onClick={() => setPage(page + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  )
}

function CaptureRow({ capture }: { capture: Capture }) {
  const analyze = useAnalyzeCaptureMutation()
  const remove = useDeleteCaptureMutation()
  const busy = analyze.isPending || remove.isPending
  const key = capture.capture_id ?? capture.id

  return (
    <tr className="align-middle">
      <td className="py-3 pr-4">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-secondary/40">
            <FlaskConical className="h-4 w-4 text-muted-foreground" />
          </div>
          <div className="min-w-0">
            <Link
              to={`/captures/${key}`}
              className="block max-w-[220px] truncate font-medium text-foreground hover:underline"
            >
              {capture.original_filename}
            </Link>
            <p className="text-xs text-muted-foreground">
              {capture.capture_format?.toUpperCase() ?? 'unknown'} · {capture.packet_count ?? '—'} packets
            </p>
          </div>
        </div>
      </td>
      <td className="py-3 pr-4">
        <code className="rounded bg-secondary/50 px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
          {truncateMiddle(capture.sha256, 10, 8)}
        </code>
      </td>
      <td className="py-3 pr-4 text-muted-foreground">{formatBytes(capture.file_size)}</td>
      <td className="py-3 pr-4">
        <StatusBadge value={capture.status} />
      </td>
      <td className="py-3 pr-4 text-muted-foreground">{formatDateTime(capture.uploaded_at)}</td>
      <td className="py-3 text-right">
        <div className="flex items-center justify-end gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={busy || capture.status === 'invalid'}
            onClick={() => analyze.mutate(key)}
            title={
              capture.status === 'invalid'
                ? 'Invalid captures cannot be analyzed'
                : 'Run packet analysis'
            }
          >
            {analyze.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Play className="h-4 w-4" />
            )}
            Analyze
          </Button>
          {analyze.isPending ? null : analyze.data ? (
            <Badge variant="success">ANL-{analyze.data.analysis_reference}</Badge>
          ) : null}
          <Button
            size="sm"
            variant="ghost"
            disabled={busy}
            onClick={() => remove.mutate(key)}
            title="Delete capture"
          >
            <Trash2 className="h-4 w-4 text-muted-foreground" />
          </Button>
        </div>
      </td>
    </tr>
  )
}