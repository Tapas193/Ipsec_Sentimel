import { useLocation } from 'react-router-dom'

import { useHealthQuery } from '@/hooks/use-api'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

const TITLES: Record<string, string> = {
  '/': 'Dashboard',
  '/captures': 'Captures',
  '/analysis': 'Analysis',
  '/findings': 'Findings',
  '/reports': 'Reports',
  '/settings': 'Settings',
}

function StatusDot({ className }: { className?: string }) {
  return (
    <span className="relative flex h-2.5 w-2.5">
      <span
        className={cn(
          'absolute inline-flex h-full w-full animate-ping rounded-full opacity-40',
          className,
        )}
      />
      <span className={cn('relative inline-flex h-2.5 w-2.5 rounded-full', className)} />
    </span>
  )
}

export function Header() {
  const { pathname } = useLocation()
  const title = TITLES[pathname] ?? 'IPsec Sentinel'
  const { data: health, isPending, isError } = useHealthQuery()
  const connected = health?.status === 'healthy' && health?.database === 'connected'

  return (
    <header className="flex h-16 shrink-0 items-center justify-between border-b border-border bg-card px-6">
      <h1 className="text-base font-semibold tracking-tight text-foreground">{title}</h1>

      <div className="flex items-center gap-4">
        {isPending ? (
          <Badge variant="outline">
            <StatusDot className="bg-muted-foreground" />
            <span className="ml-1.5">Checking API…</span>
          </Badge>
        ) : isError || !connected ? (
          <Badge variant="danger">
            <StatusDot className="bg-status-danger" />
            <span className="ml-1.5">API offline</span>
          </Badge>
        ) : (
          <Badge variant="success">
            <StatusDot className="bg-status-success" />
            <span className="ml-1.5">Database connected</span>
          </Badge>
        )}
        <span className="text-xs tabular-nums text-muted-foreground">
          v{health?.version ?? '0.1.0'}
        </span>
      </div>
    </header>
  )
}