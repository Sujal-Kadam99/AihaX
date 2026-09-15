import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Targets from './pages/Targets';
import NewAssessment from './pages/NewAssessment';
import Campaigns from './pages/Campaigns';
import Findings from './pages/Findings';
import FindingDetail from './pages/FindingDetail';
import Reports from './pages/Reports';
import Evidence from './pages/Evidence';
import Audit from './pages/Audit';
import Settings from './pages/Settings';

// Legacy / Support pages
import LiveScan from './pages/LiveScan';
import ScanHistory from './pages/ScanHistory';
import WatchMode from './pages/WatchMode';
import Billing from './pages/Billing';
import Onboarding from './pages/Onboarding';

import { ThemeProvider } from './context/ThemeContext';
import { ToastProvider } from './context/ToastContext';
import { AuthProvider } from './context/AuthContext';
import ToastContainer from './components/ui/Toast';
import ErrorBoundary from './components/ui/ErrorBoundary';

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <ToastProvider>
          <BrowserRouter>
            <ErrorBoundary>
              <Routes>
                <Route element={<Layout />}>
                {/* Simplified Desktop-First Console Routes */}
                <Route path="/" element={<Dashboard />} />
                <Route path="/targets" element={<Targets />} />
                <Route path="/new-assessment" element={<NewAssessment />} />
                <Route path="/campaigns" element={<Campaigns />} />
                <Route path="/campaigns/:id" element={<Campaigns />} />
                <Route path="/findings" element={<Findings />} />
                <Route path="/findings/:id" element={<FindingDetail />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/evidence" element={<Evidence />} />
                <Route path="/audit" element={<Audit />} />
                <Route path="/settings" element={<Settings />} />

                {/* Backward-Compatible & Support Routes */}
                <Route path="/new-scan" element={<Navigate to="/new-assessment" replace />} />
                <Route path="/scan/:scanId" element={<LiveScan />} />
                <Route path="/history" element={<ScanHistory />} />
                <Route path="/watch" element={<WatchMode />} />
                <Route path="/billing" element={<Billing />} />
                <Route path="/onboarding" element={<Onboarding />} />
              </Route>
            </Routes>
            </ErrorBoundary>
            <ToastContainer />
          </BrowserRouter>
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}
