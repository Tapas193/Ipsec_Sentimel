import { NavLink } from 'react-router-dom'
import {
  Activity,
  BarChart3,
  FileText,
  FlaskConical,
  LayoutDashboard,
  Settings,
  ShieldHalf,
  TriangleAlert,
} from 'lucide-react'

import { cn } from '@/lib/utils'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/captures', label: 'Captures', icon: FlaskConical },
  { to: '/analysis', label: 'Analysis', icon: BarChart3 },
  { to: '/findings', label: 'Findings', icon: TriangleAlert },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function Sidebar() {
  return (
    <aside className="flex h-full w-60 shrink-0 flex-col border-r border-border bg-card">
      <div className="flex h-16 items-center gap-3 border-b border-border px-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-md bg-brand/15">
          <ShieldHalf className="h-5 w-5 text-brand" strokeWidth={2} />
        </div>
        <div className="leading-tight">
          <p className="text-sm font-bold tracking-tight text-foreground">IPsec Sentinel</p>
          <p className="text-[11px] text-muted-foreground">Protocol Analyzer</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-accent text-accent-foreground ring-1 ring-inset ring-border'
                  : 'text-muted-foreground hover:bg-accent/60 hover:text-foreground',
              )
            }
          >
            <Icon className="h-4 w-4" strokeWidth={1.75} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-border p-4">
        <div className="flex items-center gap-2 rounded-md border border-border bg-secondary/40 px-3 py-2.5">
          <Activity className="h-4 w-4 text-status-success" />
<div className="text-[11px] leading-tight text-muted-foreground">
          <p className="font-medium text-foreground">Phase 1</p>
          <p>Foundation only</p>
        </div>
      </div>
    </div>
  </aside>
)
}