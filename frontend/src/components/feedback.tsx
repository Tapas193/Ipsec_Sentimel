import { Loader2 } from 'lucide-react'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

/** Shared pending state so every data view waits the same way. */
export function LoadingCard() {
  return (
    <Card>
      <CardContent className="flex items-center justify-center gap-3 py-12 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading…
      </CardContent>
    </Card>
  )
}

/** Shared error state so every data view fails the same way. */
export function ErrorCard({ message }: { message: string }) {
  return (
    <Card className="border-status-danger/40">
      <CardHeader>
        <CardTitle className="text-status-danger">Unable to load data</CardTitle>
        <CardDescription>{message}</CardDescription>
      </CardHeader>
    </Card>
  )
}
