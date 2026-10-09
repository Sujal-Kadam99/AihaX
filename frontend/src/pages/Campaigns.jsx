import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Play,
  Pause,
  XCircle,
  CheckCircle2,
  Search,
  FileText,
  Database,
  History,
  ShieldCheck,
  Activity,
  Layers,
  Server,
  Clock,
  Radio,
  AlertCircle,
  Sparkles,
  Globe,
  Network,
  ListOrdered,
  Terminal,
  CopyCheck,
  Link2,
} from 'lucide-react';
import ValidationQueue from '../components/ValidationQueue';
import RealWorldValidationQueue from '../components/RealWorldValidationQueue';
import HuntingQueue from '../components/HuntingQueue';
import AttackSurfaceGraph from '../components/AttackSurfaceGraph';
import ValidationPlanViewer from '../components/ValidationPlanViewer';
import LiveValidationConsole from '../components/LiveValidationConsole';
import ReproducibilityViewer from '../components/ReproducibilityViewer';
import EvidenceChainViewer from '../components/EvidenceChainViewer';
import ExecutionTimeline from '../components/ExecutionTimeline';
import ReconToolExecutionPanel from '../components/ReconToolExecutionPanel';
import {
  getCampaigns,
  getCampaign,
  getCampaignRuntime,
  startCampaign,
  pauseCampaign,
  resumeCampaign,
  cancelCampaign,
  verifyCampaignIntegrity,
  generateCampaignReports,
  healthCheck,
  getCampaignEvidence,
  getCampaignFindings,
  getCampaignReconDiagnostics,
  getCampaignReconRun,
} from '../lib/api';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Progress from '../components/ui/Progress';
import { useToast } from '../hooks/useToast';

export default function Campaigns() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { addToast } = useToast();

  const activeId = searchParams.get('id');
  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [runtimeTruth, setRuntimeTruth] = useState(null);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [integrityReport, setIntegrityReport] = useState(null);
  const [backendHealth, setBackendHealth] = useState('CONNECTED');
  const [evidenceCount, setEvidenceCount] = useState(0);
  const [findingsStats, setFindingsStats] = useState({ total: 0, verified: 0 });
  const [viewMode, setViewMode] = useState('overview');
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [reproductionResult, setReproductionResult] = useState(null);
  const [reconDiagnostics, setReconDiagnostics] = useState(null);
  const [reconRun, setReconRun] = useState(null);


  useEffect(() => {
    loadCampaigns();
    checkBackend();
  }, [statusFilter]);

  useEffect(() => {
    if (activeId) {
      loadCampaignDetail(activeId);
    } else if (campaigns.length > 0) {
      const firstId = campaigns[0].campaign_id || campaigns[0].id;
      setSearchParams({ id: firstId }, { replace: true });
      loadCampaignDetail(firstId);
    }
  }, [activeId, campaigns]);

  // Live polling for running/queued campaigns
  useEffect(() => {
    if (!activeId || !selectedCampaign) return;
    if (selectedCampaign.status !== 'RUNNING' && selectedCampaign.status !== 'QUEUED') return;

    const interval = setInterval(() => {
      loadCampaignDetail(activeId);
    }, 2000);

    return () => clearInterval(interval);
  }, [activeId, selectedCampaign?.status]);

  async function checkBackend() {
    try {
      const res = await healthCheck();
      if (res.data?.status === 'ok') {
        if (res.data?.redis === 'error') {
          setBackendHealth('DEGRADED (Redis Optional)');
        } else {
          setBackendHealth('CONNECTED');
        }
      } else {
        setBackendHealth('DEGRADED');
      }
    } catch {
      setBackendHealth('OFFLINE');
    }
  }

  async function loadCampaigns() {
    try {
      setLoading(true);
      const params = statusFilter === 'ALL' ? {} : { status: statusFilter };
      const res = await getCampaigns(params);
      const list = res.data?.data || res.data || [];
      setCampaigns(list);
    } catch (err) {
      console.error('Error loading campaigns:', err);
    } finally {
      setLoading(false);
    }
  }

  async function loadCampaignDetail(id) {
    try {
      const res = await getCampaign(id);
      const camp = res.data?.data || res.data;
      setSelectedCampaign(camp);

      // Query diagnostic runtime truth, evidence, and findings in parallel
      try {
        const [rtRes, evRes, fRes, diagRes, reconRunRes] = await Promise.allSettled([
          getCampaignRuntime(id),
          getCampaignEvidence(id),
          getCampaignFindings(id),
          getCampaignReconDiagnostics(id),
          getCampaignReconRun(id),
        ]);

        if (rtRes.status === 'fulfilled') {
          const truth = rtRes.value.data?.data;
          if (truth) setRuntimeTruth(truth);
        }

        if (evRes.status === 'fulfilled') {
          const raw = evRes.value.data?.data;
          const count = raw?.total_count ?? (Array.isArray(raw?.items) ? raw.items.length : (Array.isArray(raw) ? raw.length : 0));
          setEvidenceCount(count);
        }

        if (fRes.status === 'fulfilled') {
          const fList = fRes.value.data?.data || [];
          const verifiedCount = fList.filter((f) => f.verification_status === 'VERIFIED').length;
          setFindingsStats({ total: fList.length, verified: verifiedCount });
        }

        if (diagRes.status === 'fulfilled') {
          const diag = diagRes.value.data?.tool_records || diagRes.value.data?.data?.tool_records;
          if (diag) setReconDiagnostics(diag);
        }
        if (reconRunRes.status === 'fulfilled') {
          setReconRun(reconRunRes.value.data?.data || null);
        }
      } catch {
        // non-blocking
      }
    } catch (err) {
      console.error('Error loading campaign detail:', err);
    }
  }

  async function handleStart() {
    if (!selectedCampaign) return;
    const cid = selectedCampaign.campaign_id || selectedCampaign.id;
    try {
      setActionLoading(true);
      await startCampaign(cid);
      addToast({ title: 'Campaign Started', message: 'Worker tasks dispatched.', type: 'success' });
      await loadCampaignDetail(cid);
      await loadCampaigns();
    } catch (err) {
      addToast({ title: 'Start Failed', message: err.response?.data?.detail || err.message, type: 'error' });
    } finally {
      setActionLoading(false);
    }
  }

  async function handlePause() {
    if (!selectedCampaign) return;
    const cid = selectedCampaign.campaign_id || selectedCampaign.id;
    try {
      setActionLoading(true);
      await pauseCampaign(cid);
      addToast({ title: 'Campaign Paused', message: 'New worker claims halted.', type: 'warning' });
      await loadCampaignDetail(cid);
      await loadCampaigns();
    } catch (err) {
      addToast({ title: 'Pause Failed', message: err.response?.data?.detail || err.message, type: 'error' });
    } finally {
      setActionLoading(false);
    }
  }

  async function handleResume() {
    if (!selectedCampaign) return;
    const cid = selectedCampaign.campaign_id || selectedCampaign.id;
    try {
      setActionLoading(true);
      await resumeCampaign(cid);
      addToast({ title: 'Campaign Resumed', message: 'Execution resumed.', type: 'success' });
      await loadCampaignDetail(cid);
      await loadCampaigns();
    } catch (err) {
      addToast({ title: 'Resume Failed', message: err.response?.data?.detail || err.message, type: 'error' });
    } finally {
      setActionLoading(false);
    }
  }

  async function handleCancel() {
    if (!selectedCampaign) return;
    const cid = selectedCampaign.campaign_id || selectedCampaign.id;
    try {
      setActionLoading(true);
      await cancelCampaign(cid);
      addToast({ title: 'Campaign Cancelled', message: 'State marked CANCELLED.', type: 'info' });
      await loadCampaignDetail(cid);
      await loadCampaigns();
    } catch (err) {
      addToast({ title: 'Cancel Failed', message: err.response?.data?.detail || err.message, type: 'error' });
    } finally {
      setActionLoading(false);
    }
  }

  async function handleVerifyIntegrity() {
    if (!selectedCampaign) return;
    const cid = selectedCampaign.campaign_id || selectedCampaign.id;
    try {
      setActionLoading(true);
      const res = await verifyCampaignIntegrity(cid);
      const report = res.data?.data || res.data;
      setIntegrityReport(report);
      addToast({
        title: report.verified ? 'Integrity Verified' : 'Integrity Issue Detected',
        message: report.verified
          ? 'Evidence, audit chain, and snapshot verified 100%.'
          : `Issues: ${report.issues?.join(', ')}`,
        type: report.verified ? 'success' : 'error',
      });
    } catch (err) {
      addToast({ title: 'Verification Failed', message: err.response?.data?.detail || err.message, type: 'error' });
    } finally {
      setActionLoading(false);
    }
  }

  async function handleGenerateReport() {
    if (!selectedCampaign) return;
    const cid = selectedCampaign.campaign_id || selectedCampaign.id;
    try {
      setActionLoading(true);
      const res = await generateCampaignReports(cid);
      addToast({
        title: 'Report Generated',
        message: `Bug bounty report generated for ${res.data?.verified_findings_count || 0} findings.`,
        type: 'success',
      });
      navigate(`/reports`);
    } catch (err) {
      addToast({ title: 'Report Generation Failed', message: err.response?.data?.detail || err.message, type: 'error' });
    } finally {
      setActionLoading(false);
    }
  }

  const campId = selectedCampaign?.campaign_id || selectedCampaign?.id;
  const reqUsed = selectedCampaign?.requests_used || 0;
  const reqBudget = selectedCampaign?.requests_budget || selectedCampaign?.campaign_budget || 500;
  const budgetPercent = Math.min(100, Math.round((reqUsed / Math.max(1, reqBudget)) * 100));

  // Determine Pipeline & Operational State
  const isCompleted = selectedCampaign?.status === 'COMPLETED';
  const isRunning = selectedCampaign?.status === 'RUNNING';
  const isPaused = selectedCampaign?.status === 'PAUSED';
  const isAuthorized = selectedCampaign?.status === 'AUTHORIZED';
  const isCancelled = selectedCampaign?.status === 'CANCELLED';

  const isStalled = runtimeTruth?.is_stalled || false;
  const stalledReason = runtimeTruth?.stalled_reason;

  let currentPhase =
    runtimeTruth?.current_phase ||
    (isRunning
      ? 'TESTING'
      : isCompleted
      ? 'COMPLETED'
      : isPaused
      ? 'PAUSED'
      : isAuthorized
      ? 'AUTHORIZED'
      : isCancelled
      ? 'CANCELLED'
      : 'DRAFT');

  let currentOperation =
    runtimeTruth?.active_operation ||
    (isRunning
      ? 'Security check execution in progress'
      : isCompleted
      ? 'Assessment completed'
      : isPaused
      ? 'Paused by operator'
      : isCancelled
      ? 'Assessment cancelled.'
      : 'Idle');

  if (isStalled) {
    currentPhase = 'RUNNING — NO RECENT PROGRESS';
  }

  const lastActivity =
    runtimeTruth?.timestamps?.last_activity_at ||
    selectedCampaign?.completed_at ||
    selectedCampaign?.started_at ||
    selectedCampaign?.created_at ||
    new Date().toISOString();

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">
            Campaign Operations & Execution
          </h1>
          <p className="text-xs text-text-secondary mt-0.5">
            Persistent execution graph, atomic worker task leases, and cryptographic verification.
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1.5 bg-surface-2 p-1 rounded border border-border text-xs flex-wrap">
          {['ALL', 'RUNNING', 'PAUSED', 'COMPLETED', 'AUTHORIZED', 'CANCELLED', 'DRAFT'].map((f) => (
            <button
              key={f}
              onClick={() => setStatusFilter(f)}
              className={`px-2.5 py-1 rounded font-medium transition-colors ${
                statusFilter === f
                  ? 'bg-accent/20 text-accent font-semibold'
                  : 'text-text-secondary hover:text-text-primary'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid: Campaign Selector + Detail Operations Pane */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Campaigns List */}
        <div className="space-y-4">
          <Card className="p-0 bg-surface border-border overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-surface-2/40 flex items-center justify-between">
              <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                Campaigns ({campaigns.length})
              </h2>
            </div>

            {campaigns.length === 0 && !loading ? (
              <div className="p-8 text-center space-y-2">
                <ShieldAlert className="w-8 h-8 mx-auto text-text-muted" />
                <p className="text-xs text-text-secondary">No campaigns found.</p>
                <Button size="xs" variant="secondary" onClick={() => navigate('/new-assessment')}>
                  + New Assessment
                </Button>
              </div>
            ) : (
              <div className="divide-y divide-border max-h-[600px] overflow-y-auto">
                {campaigns.map((camp) => {
                  const currentId = camp.campaign_id || camp.id;
                  const isSelected = selectedCampaign && (selectedCampaign.campaign_id === currentId || selectedCampaign.id === currentId);
                  return (
                    <div
                      key={currentId}
                      onClick={() => {
                        setSelectedCampaign(camp);
                        setSearchParams({ id: currentId });
                        setIntegrityReport(null);
                      }}
                      className={`p-3.5 cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-accent/10 border-l-2 border-accent'
                          : 'hover:bg-surface-2/50'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-text-primary truncate max-w-[170px]">
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
                              : camp.status === 'CANCELLED'
                              ? 'danger'
                              : camp.status === 'AUTHORIZED'
                              ? 'accent'
                              : 'secondary'
                          }
                          size="xs"
                        >
                          {camp.status}
                        </Badge>
                      </div>
                      <div className="text-[11px] font-mono text-text-secondary truncate mt-1">
                        {camp.target_url}
                      </div>
                      <div className="text-[10px] text-text-muted mt-1 flex items-center justify-between">
                        <span>{camp.mode}</span>
                        <span>
                          {camp.requests_used || 0} / {camp.requests_budget || camp.campaign_budget || 500} reqs
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>

        {/* Right 2 Columns: Detailed Selected Campaign Controls & Live State */}
        <div className="lg:col-span-2 space-y-6">
          {selectedCampaign ? (
            <>
              {/* Mode Toggle Bar */}
              <div className="flex items-center justify-between bg-surface p-1.5 rounded-lg border border-border">
                <div className="flex items-center gap-1 flex-wrap">
                  <button
                    onClick={() => setViewMode('overview')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'overview'
                        ? 'bg-accent text-white shadow'
                        : 'text-text-secondary hover:text-text-primary'
                    }`}
                  >
                    <Activity className="w-3.5 h-3.5" /> Overview
                  </button>
                  <button
                    onClick={() => setViewMode('phase23-attack-surface')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'phase23-attack-surface'
                        ? 'bg-cyan-600 text-white shadow'
                        : 'text-text-secondary hover:text-cyan-400'
                    }`}
                  >
                    <Network className="w-3.5 h-3.5" /> Attack Surface (Phase 23)
                  </button>
                  <button
                    onClick={() => setViewMode('phase23-plans')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'phase23-plans'
                        ? 'bg-indigo-600 text-white shadow'
                        : 'text-text-secondary hover:text-indigo-400'
                    }`}
                  >
                    <ListOrdered className="w-3.5 h-3.5" /> Plans (Phase 23)
                  </button>
                  <button
                    onClick={() => setViewMode('phase23-console')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'phase23-console'
                        ? 'bg-emerald-600 text-white shadow'
                        : 'text-text-secondary hover:text-emerald-400'
                    }`}
                  >
                    <Terminal className="w-3.5 h-3.5" /> Live Console (Phase 23)
                  </button>
                  <button
                    onClick={() => setViewMode('phase23-reproducibility')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'phase23-reproducibility'
                        ? 'bg-purple-600 text-white shadow'
                        : 'text-text-secondary hover:text-purple-400'
                    }`}
                  >
                    <CopyCheck className="w-3.5 h-3.5" /> Reproducibility
                  </button>
                  <button
                    onClick={() => setViewMode('phase23-evidence-chain')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'phase23-evidence-chain'
                        ? 'bg-blue-600 text-white shadow'
                        : 'text-text-secondary hover:text-blue-400'
                    }`}
                  >
                    <Link2 className="w-3.5 h-3.5" /> Evidence Chain
                  </button>
                  <button
                    onClick={() => setViewMode('real-world')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'real-world'
                        ? 'bg-emerald-600 text-white shadow'
                        : 'text-text-secondary hover:text-emerald-400'
                    }`}
                  >
                    <Globe className="w-3.5 h-3.5" /> Real-World (Phase 22)
                  </button>
                  <button
                    onClick={() => setViewMode('validation')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'validation'
                        ? 'bg-accent text-white shadow'
                        : 'text-text-secondary hover:text-text-primary'
                    }`}
                  >
                    <ShieldCheck className="w-3.5 h-3.5" /> Controlled (Phase 21)
                  </button>
                  <button
                    onClick={() => setViewMode('phase25-recon-tools')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'phase25-recon-tools'
                        ? 'bg-amber-600 text-white shadow'
                        : 'text-text-secondary hover:text-amber-400'
                    }`}
                  >
                    <ShieldCheck className="w-3.5 h-3.5" /> Recon Tools (Phase 25)
                  </button>
                  <button
                    onClick={() => setViewMode('hunting')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'hunting'
                        ? 'bg-accent text-white shadow'
                        : 'text-text-secondary hover:text-text-primary'
                    }`}
                  >
                    <Sparkles className="w-3.5 h-3.5" /> Hunting (Phase 20)
                  </button>
                  <button
                    onClick={() => setViewMode('timeline')}
                    className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                      viewMode === 'timeline'
                        ? 'bg-accent text-white shadow'
                        : 'text-text-secondary hover:text-text-primary'
                    }`}
                  >
                    <Clock className="w-3.5 h-3.5" /> Timeline
                  </button>
                  <button
                    onClick={() => navigate(`/evidence?campaign=${selectedCampaign.campaign_id || selectedCampaign.id}`)}
                    className="px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors text-text-secondary hover:text-cyan-400 border border-border/40 hover:border-cyan-500/40"
                    title="Open Evidence Vault"
                  >
                    <Database className="w-3.5 h-3.5 text-accent" /> Evidence
                  </button>
                </div>

                <Badge variant={selectedCampaign.status === 'RUNNING' ? 'success' : 'secondary'} size="xs">
                  {selectedCampaign.status}
                </Badge>
              </div>

              {viewMode === 'phase23-attack-surface' ? (
                <AttackSurfaceGraph
                  campaignId={selectedCampaign.campaign_id || selectedCampaign.id}
                  targetUrl={selectedCampaign.target_url}
                />
              ) : viewMode === 'phase23-plans' ? (
                <ValidationPlanViewer
                  campaignId={selectedCampaign.campaign_id || selectedCampaign.id}
                  targetUrl={selectedCampaign.target_url}
                  onSelectPlan={(plan) => setSelectedPlan(plan)}
                />
              ) : viewMode === 'phase23-console' ? (
                <LiveValidationConsole
                  campaignId={selectedCampaign.campaign_id || selectedCampaign.id}
                  targetUrl={selectedCampaign.target_url}
                  selectedPlan={selectedPlan}
                  onExecutionComplete={(res) => {
                    setReproductionResult(res);
                    loadCampaignDetail(selectedCampaign.campaign_id || selectedCampaign.id);
                  }}
                />
              ) : viewMode === 'phase23-reproducibility' ? (
                <ReproducibilityViewer reproductionResult={reproductionResult} />
              ) : viewMode === 'phase23-evidence-chain' ? (
                <EvidenceChainViewer
                  campaignId={selectedCampaign.campaign_id || selectedCampaign.id}
                  planId={selectedPlan?.id || 'PLAN-DEFAULT'}
                />
              ) : viewMode === 'real-world' ? (
                <RealWorldValidationQueue
                  campaignId={selectedCampaign.campaign_id || selectedCampaign.id}
                  targetUrl={selectedCampaign.target_url}
                  onVerificationComplete={() => {
                    loadCampaignDetail(selectedCampaign.campaign_id || selectedCampaign.id);
                  }}
                />
              ) : viewMode === 'validation' ? (
                <ValidationQueue
                  campaignId={selectedCampaign.campaign_id || selectedCampaign.id}
                  targetUrl={selectedCampaign.target_url}
                  onVerificationComplete={() => {
                    loadCampaignDetail(selectedCampaign.campaign_id || selectedCampaign.id);
                  }}
                />
              ) : viewMode === 'phase25-recon-tools' ? (
                <ReconToolExecutionPanel
                  validationResult={{
                    target: selectedCampaign.target_url,
                    campaign_id: selectedCampaign.campaign_id || selectedCampaign.id,
                    tool_records: reconDiagnostics,
                  }}
                />
              ) : viewMode === 'hunting' ? (
                <HuntingQueue
                  campaignId={selectedCampaign.campaign_id || selectedCampaign.id}
                  targetUrl={selectedCampaign.target_url}
                  requestsUsed={selectedCampaign.requests_used || 0}
                  maxBudget={selectedCampaign.requests_budget || selectedCampaign.campaign_budget || 10}
                />
              ) : viewMode === 'timeline' ? (
                <ExecutionTimeline
                  campaignId={selectedCampaign.campaign_id || selectedCampaign.id}
                  onSelectEvidence={() => navigate(`/evidence?campaign=${selectedCampaign.campaign_id || selectedCampaign.id}`)}
                />
              ) : (
                <>
                  {/* Campaign Header & Controls Card */}
                  <Card className="p-5 bg-surface border-border space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
                      <div>
                        <div className="flex items-center gap-2">
                          <h2 className="text-base font-bold text-text-primary">
                            {selectedCampaign.name}
                          </h2>
                          <Badge
                        variant={
                          selectedCampaign.status === 'RUNNING'
                            ? 'success'
                            : selectedCampaign.status === 'PAUSED'
                            ? 'warning'
                            : selectedCampaign.status === 'COMPLETED'
                            ? 'info'
                            : selectedCampaign.status === 'CANCELLED'
                            ? 'danger'
                            : selectedCampaign.status === 'AUTHORIZED'
                            ? 'accent'
                            : 'secondary'
                        }
                      >
                        {selectedCampaign.status}
                      </Badge>
                      {selectedCampaign.is_authorization_expired ? (
                        <Badge variant="danger" size="xs">
                          AUTH EXPIRED
                        </Badge>
                      ) : selectedCampaign.authorization_expires_at ? (
                        <Badge variant="secondary" size="xs">
                          Auth valid: {new Date(selectedCampaign.authorization_expires_at).toLocaleDateString()}
                        </Badge>
                      ) : null}
                    </div>
                    <div className="text-xs font-mono text-text-secondary mt-1">
                      {selectedCampaign.target_url} &bull; Mode: {selectedCampaign.mode}
                      {selectedCampaign.authorized_by && ` • Authorized By: ${selectedCampaign.authorized_by}`}
                    </div>
                  </div>

                  {/* Operational Control Buttons */}
                  <div className="flex items-center gap-2 flex-wrap">
                    {selectedCampaign.status === 'AUTHORIZED' && (
                      <Button
                        variant="primary"
                        size="xs"
                        loading={actionLoading}
                        onClick={handleStart}
                        className="flex items-center gap-1"
                      >
                        <Play className="w-3.5 h-3.5" /> Start
                      </Button>
                    )}

                    {selectedCampaign.status === 'RUNNING' && (
                      <Button
                        variant="secondary"
                        size="xs"
                        loading={actionLoading}
                        onClick={handlePause}
                        className="flex items-center gap-1 text-amber-400"
                      >
                        <Pause className="w-3.5 h-3.5" /> Pause
                      </Button>
                    )}

                    {selectedCampaign.status === 'PAUSED' && (
                      <Button
                        variant="primary"
                        size="xs"
                        loading={actionLoading}
                        onClick={handleResume}
                        className="flex items-center gap-1"
                      >
                        <Play className="w-3.5 h-3.5" /> Resume
                      </Button>
                    )}

                    {(selectedCampaign.status === 'RUNNING' ||
                      selectedCampaign.status === 'PAUSED' ||
                      selectedCampaign.status === 'DRAFT' ||
                      selectedCampaign.status === 'AUTHORIZED') && (
                      <Button
                        variant="danger"
                        size="xs"
                        loading={actionLoading}
                        onClick={handleCancel}
                        className="flex items-center gap-1"
                      >
                        <XCircle className="w-3.5 h-3.5" /> Cancel
                      </Button>
                    )}

                    <Button
                      variant="secondary"
                      size="xs"
                      loading={actionLoading}
                      onClick={handleVerifyIntegrity}
                      className="flex items-center gap-1 text-accent"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" /> Verify Integrity
                    </Button>
                  </div>
                </div>

                {/* Stalled Alert Banner */}
                {isStalled && (
                  <div className="p-3 rounded bg-amber-500/10 border border-amber-500/30 flex items-start gap-2.5 text-xs text-amber-300">
                    <AlertCircle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                    <div>
                      <div className="font-semibold text-amber-400">RUNNING — NO RECENT PROGRESS</div>
                      <div className="text-[11px] text-amber-200/80 mt-0.5">
                        {stalledReason || 'No active worker lease or task progress within threshold. Security assessment is stalled.'}
                      </div>
                    </div>
                  </div>
                )}

                {/* Runtime State Visibility Panel */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded bg-surface-2/70 border border-border text-xs">
                  <div>
                    <div className="text-[10px] text-text-muted uppercase font-semibold flex items-center gap-1">
                      <Server className="w-3 h-3 text-accent" /> Backend State
                    </div>
                    <div className="font-mono font-semibold text-emerald-400 mt-0.5">
                      {backendHealth}
                    </div>
                    <div className="text-[10px] font-mono text-text-muted mt-0.5">
                      DB: READY &bull; Redis: OPTIONAL
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-text-muted uppercase font-semibold flex items-center gap-1">
                      <Radio className="w-3 h-3 text-accent" /> Current Phase
                    </div>
                    <div className={`font-mono font-semibold mt-0.5 ${isStalled ? 'text-amber-400' : 'text-text-primary'}`}>
                      {currentPhase}
                    </div>
                    <div className="text-[10px] font-mono text-text-muted mt-0.5">
                      {evidenceCount} ev &bull; {findingsStats.verified} verified
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-text-muted uppercase font-semibold flex items-center gap-1">
                      <Activity className="w-3 h-3 text-accent" /> Active Operation
                    </div>
                    <div className="font-mono text-text-secondary mt-0.5 truncate" title={currentOperation}>
                      {currentOperation}
                    </div>
                    <div className="text-[10px] font-mono text-text-muted mt-0.5">
                      Tasks: {runtimeTruth?.tasks_summary?.COMPLETED || 0} done, {runtimeTruth?.tasks_summary?.RUNNING || 0} active
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-text-muted uppercase font-semibold flex items-center gap-1">
                      <Clock className="w-3 h-3 text-accent" /> Last Activity
                    </div>
                    <div className="font-mono text-text-muted mt-0.5 truncate text-[11px]">
                      {new Date(lastActivity).toLocaleTimeString()}
                    </div>
                    <div className="text-[10px] font-mono text-text-muted mt-0.5">
                      {runtimeTruth ? `${runtimeTruth.time_since_last_activity_sec}s ago` : 'Live'}
                    </div>
                  </div>
                </div>

                {/* Pipeline Progress Stages */}
                <div className="py-2">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-2">
                    Assessment Pipeline
                  </div>
                  <div className="grid grid-cols-6 gap-2 text-center text-[11px]">
                    <div className="p-2 rounded bg-surface-2 border border-border text-emerald-400 font-semibold">
                      <CheckCircle2 className="w-3.5 h-3.5 mx-auto mb-1" />
                      Scope
                    </div>
                    <div
                      className={`p-2 rounded border font-medium ${
                        isRunning || isCompleted
                          ? 'bg-surface-2 border-border text-emerald-400 font-semibold'
                          : 'bg-surface-2/40 border-border text-text-muted'
                      }`}
                    >
                      <Activity className="w-3.5 h-3.5 mx-auto mb-1" />
                      Recon
                    </div>
                    <div
                      className={`p-2 rounded border font-medium ${
                        isRunning
                          ? 'bg-accent/15 border-accent text-accent font-semibold'
                          : isCompleted
                          ? 'bg-surface-2 border-border text-emerald-400 font-semibold'
                          : 'bg-surface-2/40 border-border text-text-muted'
                      }`}
                    >
                      <Layers className="w-3.5 h-3.5 mx-auto mb-1" />
                      Testing
                    </div>
                    <div
                      className={`p-2 rounded border font-medium ${
                        isRunning
                          ? 'bg-accent/15 border-accent text-accent'
                          : isCompleted
                          ? 'bg-surface-2 border-border text-emerald-400 font-semibold'
                          : 'bg-surface-2/40 border-border text-text-muted'
                      }`}
                    >
                      <ShieldCheck className="w-3.5 h-3.5 mx-auto mb-1" />
                      Verification
                    </div>
                    <div
                      className={`p-2 rounded border font-medium ${
                        isCompleted
                          ? 'bg-surface-2 border-border text-emerald-400 font-semibold'
                          : 'bg-surface-2/40 border-border text-text-muted'
                      }`}
                    >
                      <Search className="w-3.5 h-3.5 mx-auto mb-1" />
                      Findings
                    </div>
                    <div
                      className={`p-2 rounded border font-medium ${
                        isCompleted
                          ? 'bg-surface-2 border-border text-emerald-400 font-semibold'
                          : 'bg-surface-2/40 border-border text-text-muted'
                      }`}
                    >
                      <FileText className="w-3.5 h-3.5 mx-auto mb-1" />
                      Report
                    </div>
                  </div>
                </div>

                {reconRun && (
                  <div className="rounded border border-border bg-surface-2/50 p-3 space-y-2 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-text-primary">Shared Recon Run</span>
                      <Badge variant={reconRun.state === 'COMPLETED' ? 'success' : reconRun.state === 'RUNNING' ? 'accent' : ['FAILED', 'BLOCKED'].includes(reconRun.state) ? 'danger' : 'secondary'}>
                        {reconRun.state}
                      </Badge>
                    </div>
                    {reconRun.failure_reason && <p className="text-rose-300">{reconRun.failure_reason}</p>}
                    {reconRun.result && (
                      <div className="text-text-secondary space-y-1">
                        <p>Tools recorded: {Object.keys(reconRun.result.tool_records || {}).length} &bull; Endpoints found: {reconRun.result.endpoint_discovery?.count ?? 0} &bull; Login surfaces: {reconRun.result.endpoint_discovery?.login_surfaces?.length ?? 0}</p>
                        <p>Host follow-up: {reconRun.result.host_followup_summary?.hosts_followed_up ?? 0} &bull; Nmap/Gobuster: {reconRun.selected_capabilities?.length ? reconRun.selected_capabilities.join(', ') : 'not selected'}</p>
                        <div className="flex flex-wrap gap-1 pt-1">
                          {Object.entries(reconRun.result.tool_records || {}).map(([toolName, record]) => (
                            <span key={toolName} title={record.failure_reason || record.status} className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px]">
                              {toolName}: {record.status}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Detailed Metric Counters */}
                <div className="grid grid-cols-3 gap-3 text-xs">
                  <div className="p-2.5 rounded bg-surface-2/50 border border-border">
                    <div className="text-[10px] text-text-muted">Evidence Captured</div>
                    <div className="text-sm font-bold font-mono text-text-primary mt-0.5">{evidenceCount}</div>
                  </div>
                  <div className="p-2.5 rounded bg-surface-2/50 border border-border">
                    <div className="text-[10px] text-text-muted">Candidate Findings</div>
                    <div className="text-sm font-bold font-mono text-text-primary mt-0.5">{findingsStats.total}</div>
                  </div>
                  <div className="p-2.5 rounded bg-surface-2/50 border border-border">
                    <div className="text-[10px] text-text-muted">Verified Findings</div>
                    <div className="text-sm font-bold font-mono text-emerald-400 mt-0.5">{findingsStats.verified}</div>
                  </div>
                </div>

                {/* Request Budget Progress */}
                <div className="space-y-1.5 pt-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-text-secondary font-medium">Request Budget Consumption</span>
                    <span className="font-mono text-text-primary">
                      {reqUsed} / {reqBudget} requests ({budgetPercent}%)
                    </span>
                  </div>
                  <Progress value={budgetPercent} />
                </div>

                {/* Integrity Report Alert if run */}
                {integrityReport && (
                  <div
                    className={`p-3 rounded border text-xs ${
                      integrityReport.verified
                        ? 'bg-emerald-950/30 border-emerald-800 text-emerald-300'
                        : 'bg-rose-950/30 border-rose-800 text-rose-300'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 font-bold">
                      <ShieldCheck className="w-4 h-4" />
                      Cryptographic Audit:{' '}
                      {integrityReport.verified ? 'PASSED (100% Deterministic Integrity)' : 'FAILED'}
                    </div>
                    <div className="font-mono text-[10px] mt-1 space-y-0.5 opacity-90">
                      <div>Snapshot: {integrityReport.checks?.snapshot ? 'VALID' : 'CORRUPTED'}</div>
                      <div>Evidence Vault: {integrityReport.checks?.evidence ? 'VALID' : 'CORRUPTED'}</div>
                      <div>Audit Trail: {integrityReport.checks?.audit_trail ? 'VALID' : 'BROKEN'}</div>
                    </div>
                  </div>
                )}

                {/* Fast Link Bar */}
                <div className="flex items-center gap-2 pt-3 border-t border-border flex-wrap">
                  <Button
                    variant="secondary"
                    size="xs"
                    onClick={() => navigate(`/findings?campaign=${campId}`)}
                    className="flex items-center gap-1.5"
                  >
                    <Search className="w-3.5 h-3.5 text-accent" /> View Findings
                  </Button>
                  <Button
                    variant="secondary"
                    size="xs"
                    onClick={() => navigate(`/evidence?campaign=${campId}`)}
                    className="flex items-center gap-1.5"
                  >
                    <Database className="w-3.5 h-3.5 text-accent" /> View Evidence Vault
                  </Button>
                  <Button
                    variant="secondary"
                    size="xs"
                    onClick={() => navigate(`/audit?campaign=${campId}`)}
                    className="flex items-center gap-1.5"
                  >
                    <History className="w-3.5 h-3.5 text-accent" /> Audit Trail
                  </Button>
                  <Button
                    variant="secondary"
                    size="xs"
                    onClick={handleGenerateReport}
                    className="flex items-center gap-1.5 text-emerald-400"
                  >
                    <FileText className="w-3.5 h-3.5" /> Generate Bug Bounty Report
                  </Button>
                </div>
              </Card>
                </>
              )}
            </>
          ) : (
            <Card className="p-8 text-center bg-surface border-border">
              <p className="text-xs text-text-secondary">Select a campaign from the left pane.</p>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
