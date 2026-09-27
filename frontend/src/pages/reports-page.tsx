import { FileText } from 'lucide-react'

import { EmptyState } from '@/components/empty-state'
import { useHealthQuery } from '@/hooks/use-api'

export function ReportsPage() {
  const { data: health } = useHealthQuery()
  const connected = health?.database === 'connected'

  return (
    <EmptyState
      icon={FileText}
      title="No reports"
      description={
        connected
          ? 'No reports have been generated yet. Report generation arrives in later phases.'
          : 'The backend is unreachable. Start the backend to view reports.'
      }
    />
  )
}