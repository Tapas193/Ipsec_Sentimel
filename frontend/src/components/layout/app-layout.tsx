import { Outlet } from 'react-router-dom'

import { Sidebar } from '@/components/layout/sidebar'
import { Header } from '@/components/layout/header'

export function AppLayout() {
  return (
    <div className="relative flex h-screen w-full overflow-hidden bg-background text-foreground">
      <div className="app-grid-backdrop pointer-events-none absolute inset-0" aria-hidden />
      <div className="relative z-10 flex h-full w-full bg-background/80">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col bg-background/60">
          <div className="flex h-full flex-col">
            <Header />
            <main className="min-h-0 flex-1 overflow-y-auto p-6">
              <Outlet />
            </main>
          </div>
        </div>
      </div>
    </div>
  )
}