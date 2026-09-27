import { Server, Database, Package, Wrench } from 'lucide-react'

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useSystemInfoQuery, useToolsQuery } from '@/hooks/use-api'

export function SettingsPage() {
  const { data: systemInfo, isPending, isError } = useSystemInfoQuery()

  return (
    <div className="space-y-6">
      <section className="flex flex-col gap-1.5">
        <h2 className="text-xl font-bold tracking-tight text-foreground">Settings</h2>
        <p className="text-sm text-muted-foreground">
          Application and environment configuration. No security parameters are shown here.
        </p>
      </section>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Package className="h-4 w-4 text-brand" /> Application
          </CardTitle>
          <CardDescription>
            Read-only system information reported by the backend.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isPending ? (
            <p className="text-sm text-muted-foreground">Loading system info…</p>
          ) : isError || !systemInfo ? (
            <p className="text-sm text-status-danger">
              Backend unreachable. Start the backend to read system information.
            </p>
          ) : (
            <dl className="grid grid-cols-2 gap-x-8 gap-y-4 text-sm md:grid-cols-3">
              <div className="space-y-1">
                <dt className="flex items-center gap-1.5 text-xs uppercase tracking-wider text-muted-foreground">
                  <Server className="h-3.5 w-3.5" /> Application
                </dt>
                <dd className="font-medium text-foreground">{systemInfo.application}</dd>
              </div>
              <div className="space-y-1">
                <dt className="text-xs uppercase tracking-wider text-muted-foreground">Version</dt>
                <dd className="font-mono text-foreground">{systemInfo.version}</dd>
              </div>
              <div className="space-y-1">
                <dt className="text-xs uppercase tracking-wider text-muted-foreground">
                  Environment
                </dt>
                <dd className="font-mono text-foreground">{systemInfo.environment}</dd>
              </div>
              <div className="space-y-1">
                <dt className="text-xs uppercase tracking-wider text-muted-foreground">Python</dt>
                <dd className="font-mono text-foreground">{systemInfo.python_version}</dd>
              </div>
              {systemInfo.components.map((component) => (
                <div key={component.name} className="space-y-1">
                  <dt className="text-xs uppercase tracking-wider text-muted-foreground">
                    {component.name}
                  </dt>
                  <dd className="font-mono text-foreground">
                    {component.status}
                    {component.detail ? ` — ${component.detail}` : ''}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </CardContent>
      </Card>

      <ToolsCard />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-4 w-4 text-brand" /> Phase 2 scope
          </CardTitle>
          <CardDescription>
            Packet analysis capabilities added in Phase 2.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="grid gap-2 text-sm text-muted-foreground md:grid-cols-2">
            <li className="rounded-md border border-border bg-secondary/40 px-3 py-2">
              PCAP/PCAPNG upload, validation and SHA-256 integrity
            </li>
            <li className="rounded-md border border-border bg-secondary/40 px-3 py-2">
              IKE/ESP/AH packet parsing and protocol detection
            </li>
            <li className="rounded-md border border-border bg-secondary/40 px-3 py-2">
              Bidirectional flow building and feature extraction
            </li>
            <li className="rounded-md border border-border bg-secondary/40 px-3 py-2">
              Not yet: AI/ML scoring, recommendations, live capture (Phase 3)
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>
  )
}

function ToolsCard() {
  const { data, isPending, isError } = useToolsQuery()

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Wrench className="h-4 w-4 text-brand" /> Packet tools
        </CardTitle>
        <CardDescription>
          Detection tools discovered on the backend host. Unknown values are reported honestly.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isPending ? (
          <p className="text-sm text-muted-foreground">Probing tools…</p>
        ) : isError || !data ? (
          <p className="text-sm text-status-danger">
            Backend unreachable. Start the backend to probe installed tools.
          </p>
        ) : (
          <div className="space-y-3">
            <p className="text-xs uppercase tracking-wider text-muted-foreground">
              Active reader: <span className="font-mono normal-case">{data.active_reader}</span>
            </p>
            <div className="grid gap-2 text-sm md:grid-cols-2">
              {data.tools.map((tool) => (
                <div
                  key={tool.name}
                  className="rounded-md border border-border bg-secondary/40 px-3 py-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-medium text-foreground">{tool.name}</span>
                    <Badge variant={tool.installed ? 'success' : 'outline'}>
                      {tool.installed ? 'installed' : 'missing'}
                    </Badge>
                  </div>
                  {tool.version ? (
                    <p className="mt-0.5 text-xs text-muted-foreground">v{tool.version}</p>
                  ) : null}
                  {tool.detail ? (
                    <p className="mt-0.5 text-xs text-muted-foreground">{tool.detail}</p>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}