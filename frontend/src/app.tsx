import { Route, Routes } from 'react-router-dom'

import { AppLayout } from '@/components/layout/app-layout'
import { DashboardPage } from '@/pages/dashboard-page'
import { CapturesPage } from '@/pages/captures-page'
import { CaptureDetailPage } from '@/pages/capture-detail-page'
import { AnalysisPage } from '@/pages/analysis-page'
import { AnalysisDetailPage } from '@/pages/analysis-detail-page'
import { FindingsPage } from '@/pages/findings-page'
import { ReportsPage } from '@/pages/reports-page'
import { SettingsPage } from '@/pages/settings-page'

export function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="captures" element={<CapturesPage />} />
        <Route path="captures/:captureKey" element={<CaptureDetailPage />} />
        <Route path="analysis" element={<AnalysisPage />} />
        <Route path="analysis/:analysisKey" element={<AnalysisDetailPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<DashboardPage />} />
      </Route>
    </Routes>
  )
}