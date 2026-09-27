import { Badge } from '@/components/ui/badge'

const MAP: Record<string, 'success' | 'warning' | 'danger' | 'info' | 'secondary'> = {
  valid: 'success',
  uploaded: 'secondary',
  analyzing: 'warning',
  analyzed: 'success',
  invalid: 'danger',
  failed: 'danger',
  analyzing_pending: 'secondary',
  completed: 'success',
  running: 'warning',
  partial: 'warning',
  queued: 'secondary',
  yes: 'success',
  no: 'danger',
  // Severity
  critical: 'danger',
  high: 'success',
  medium: 'warning',
  low: 'info',
  info: 'info',
  // Finding status
  open: 'secondary',
  acknowledged: 'warning',
  resolved: 'success',
}

export function StatusBadge({ value }: { value: string | null | undefined }) {
  if (!value) {
    return <Badge variant="outline">unknown</Badge>
  }
  return (
    <Badge variant={MAP[value.toLowerCase()] ?? 'secondary'}>{value}</Badge>
  )
}