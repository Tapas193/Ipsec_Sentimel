import { TriangleAlert } from 'lucide-react'

import { EmptyState } from '@/components/empty-state'
import { useHealthQuery } from '@/hooks/use-api'

export function FindingsPage() {
  const { data: health } = useHealthQuery()
  const connected = health?.database === 'connected'

  return (
    <EmptyState
      icon={TriangleAlert}
      title="No findings"
      description={
        connected
          ? 'No security findings have been recorded yet. Detection rules arrive in later phases.'
          : 'The backend is unreachable. Start the backend to view findings.'
      }
    />
  )
}