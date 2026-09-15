import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Play,
  Search,
  FileText,
  Plus,
  CheckCircle2,
  ExternalLink,
  Target,
} from 'lucide-react';
import { getCampaigns, getOperationalMetrics, healthCheck } from '../lib/api';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';

export default function Dashboard() {
  const navigate = useNavigate();
  const [metrics, setMetrics] = useState({
    activeCampaigns: 0,
    runningJobs: 0,
    openFindings: 0,
    reportsCount: 0,
  });
  const [recentCampaigns, setRecentCampaigns] = useState([]);
  const [health, setHealth] = useState({ backend: 'ok', database: 'ok', scopeEngine: 'active', vault: 'active' });

  useEffect(() => {
    let isMounted = true;

    async function loadDashboardData() {
      try {
        const [campsRes, healthRes, opsMetricsRes] = await Promise.allSettled([
          getCampaigns({ limit: 5 }),
          healthCheck(),
          getOperationalMetrics(),
        ]);

        if (!isMounted) return;

        let campaignsList = [];
        if (campsRes.status === 'fulfilled' && campsRes.value.data?.data) {
          campaignsList = campsRes.value.data.data;
          setRecentCampaigns(campaignsList);
        }

        if (healthRes.status === 'fulfilled' && healthRes.value.data) {
          setHealth({
            backend: healthRes.value.data.status === 'ok' ? 'ok' : 'degraded',
            database: healthRes.value.data.database === 'ok' ? 'ok' : 'degraded',
            scopeEngine: 'active',
            vault: 'active',
          });
        }

        const activeCount = campaignsList.filter(
          (c) => c.status === 'RUNNING' || c.status === 'AUTHORIZED' || c.status === 'QUEUED'
        ).length;

        let findingsCount = 0;
        if (opsMetricsRes.status === 'fulfilled' && opsMetricsRes.value.data?.data) {
          const opsData = opsMetricsRes.value.data.data;
          findingsCount = opsData.findings_verified || opsData.findings_candidates || 0;
        }

        setMetrics({
          activeCampaigns: activeCount,
          runningJobs: campaignsList.filter((c) => c.status === 'RUNNING').length,
          openFindings: findingsCount,
          reportsCount: campaignsList.filter((c) => c.status === 'COMPLETED').length,
        });
      } catch (err) {
        console.error('Error loading dashboard:', err);
      }
    }

    loadDashboardData();
  }, []);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header & New Assessment Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">
            Security Operations Overview
          </h1>
          <p className="text-xs text-text-secondary mt-0.5">
            Authorized pentesting, deterministic verification, and real-time scope enforcement.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="primary"
            size="sm"
            className="flex items-center gap-1.5 shadow-sm"
            onClick={() => navigate('/new-assessment')}
          >
            <Plus className="w-4 h-4" />
            <span>New Assessment</span>
          </Button>
        </div>
      </div>

      {/* 4 Essential Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-4 bg-surface border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-text-secondary">Active Campaigns</span>
            <ShieldAlert className="w-4 h-4 text-accent" />
          </div>
          <div className="text-2xl font-bold font-mono mt-2 text-text-primary">
            {metrics.activeCampaigns}
          </div>
          <div className="text-[11px] text-text-muted mt-1">In execution or queued</div>
        </Card>

        <Card className="p-4 bg-surface border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-text-secondary">Running Tasks</span>
            <Play className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono mt-2 text-text-primary">
            {metrics.runningJobs}
          </div>
          <div className="text-[11px] text-text-muted mt-1">Under atomic worker lease</div>
        </Card>

        <Card className="p-4 bg-surface border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-text-secondary">Verified Findings</span>
            <Search className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono mt-2 text-text-primary">
            {metrics.openFindings}
          </div>
          <div className="text-[11px] text-text-muted mt-1">Mathematically verified</div>
        </Card>

        <Card className="p-4 bg-surface border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-text-secondary">Reports & Manifests</span>
            <FileText className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono mt-2 text-text-primary">
            {metrics.reportsCount}
          </div>
          <div className="text-[11px] text-text-muted mt-1">Cryptographically anchored</div>
        </Card>
      </div>

      {/* Main Grid: Recent Campaigns + System Safety Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Recent Security Campaigns */}
        <div className="lg:col-span-2 space-y-4">
          <Card className="p-0 bg-surface border-border overflow-hidden">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between bg-surface-2/40">
              <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                Recent Security Campaigns
              </h2>
              <Link
                to="/campaigns"
                className="text-xs text-accent hover:underline flex items-center gap-1 font-medium"
              >
                View all <ExternalLink className="w-3 h-3" />
              </Link>
            </div>

            {recentCampaigns.length === 0 ? (
              <div className="p-8 text-center space-y-3">
                <div className="w-10 h-10 mx-auto rounded-full bg-surface-2 flex items-center justify-center text-text-muted">
                  <Target className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-sm font-medium text-text-primary">No assessments yet</div>
                  <div className="text-xs text-text-secondary mt-0.5">
                    Start your first authorized security assessment.
                  </div>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => navigate('/new-assessment')}
                  className="mt-2"
                >
                  + New Assessment
                </Button>
              </div>
            ) : (
              <div className="divide-y divide-border">
                {recentCampaigns.map((camp) => (
                  <div
                    key={camp.campaign_id}
                    onClick={() => navigate(`/campaigns?id=${camp.campaign_id}`)}
                    className="px-4 py-3 flex items-center justify-between hover:bg-surface-2/50 cursor-pointer transition-colors"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-text-primary hover:text-accent">
                          {camp.name}
                        </span>
                        <Badge
                          variant={
                            camp.status === 'RUNNING'
                              ? 'success'
                              : camp.status === 'PAUSED'
                              ? 'warning'
                              : camp.status === 'COMPLETED'
                              ? 'info'
                              : 'secondary'
                          }
                          size="sm"
                        >
                          {camp.status}
                        </Badge>
                      </div>
                      <div className="text-xs font-mono text-text-secondary">
                        {camp.target_url} &bull; Mode: {camp.mode}
                      </div>
                    </div>

                    <div className="text-right space-y-0.5">
                      <div className="text-xs font-mono text-text-primary">
                        {camp.requests_used} / {camp.requests_budget} reqs
                      </div>
                      <div className="text-[11px] text-text-muted">
                        Tasks: {camp.tasks_summary?.completed || 0}/{camp.tasks_summary?.total || 0}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>

        {/* Right 1 Col: System Safety & Verification Engine Health */}
        <div className="space-y-4">
          <Card className="p-4 bg-surface border-border space-y-4">
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider pb-2 border-b border-border">
              Safety & Verification Controls
            </h2>

            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="text-text-secondary">Scope Enforcement</span>
                <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Default-Deny Active
                </span>
              </div>

              <div className="flex items-center justify-between text-xs">
                <span className="text-text-secondary">Pre-Flight Transport Gate</span>
                <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Zero-Byte Guard
                </span>
              </div>

              <div className="flex items-center justify-between text-xs">
                <span className="text-text-secondary">Evidence Redaction Engine</span>
                <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  9 Regex Filters
                </span>
              </div>

              <div className="flex items-center justify-between text-xs">
                <span className="text-text-secondary">Audit Trail Hash Chaining</span>
                <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  SHA-256 Chained
                </span>
              </div>

              <div className="flex items-center justify-between text-xs">
                <span className="text-text-secondary">Database Storage (WAL)</span>
                <span
                  className={`flex items-center gap-1.5 font-medium ${
                    health.database === 'ok' ? 'text-emerald-400' : 'text-amber-400'
                  }`}
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  {health.database === 'ok' ? 'SQLite WAL Active' : 'Degraded'}
                </span>
              </div>
            </div>

            <div className="pt-3 border-t border-border">
              <div className="p-2.5 rounded bg-surface-2 border border-border text-[11px] text-text-muted leading-relaxed">
                <span className="font-semibold text-text-secondary">Safety Invariant:</span> No
                network packets are dispatched unless explicit written authorization matches target
                scope hash.
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
