import type { LucideIcon } from 'lucide-react'

import { Card, CardContent } from '@/components/ui/card'
import { cn, formatCount } from '@/lib/utils'

export function StatCard({
  icon: Icon,
  label,
  value,
  hint,
  tone = 'info',
}: {
  icon: LucideIcon
  label: string
  value: number | string
  hint?: string
  tone?: 'info' | 'success' | 'warning' | 'danger'
}) {
  const toneClass = {
    info: 'text-status-info',
    success: 'text-status-success',
    warning: 'text-status-warning',
    danger: 'text-status-danger',
  }[tone]

  return (
    <Card className="overflow-hidden">
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              {label}
            </p>
            <p className="font-mono text-3xl font-semibold tabular-nums text-foreground">
              {typeof value === 'number' ? formatCount(value) : value}
            </p>
            {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
          </div>
          <div className={cn('rounded-md border border-border bg-secondary/40 p-2.5', toneClass)}>
            <Icon className="h-5 w-5" strokeWidth={1.75} />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}