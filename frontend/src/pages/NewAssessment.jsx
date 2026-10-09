import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  CheckCircle2,
  XCircle,
  Play,
  Lock,
  ShieldCheck,
  Globe,
  RefreshCw,
} from 'lucide-react';
import {
  getPrograms,
  validateTargetScope,
  createCampaign,
  authorizeCampaign,
  startCampaign,
} from '../lib/api';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Alert from '../components/ui/Alert';
import ErrorBoundary from '../components/ui/ErrorBoundary';
import { useToast } from '../hooks/useToast';
import { validateConcreteTargetUrl } from '../utils/urlValidator';
import {
  normalizeScopeRules,
  normalizeMatchedRule,
  normalizeReason,
} from '../utils/scopeNormalizers';

export default function NewAssessment() {
  const navigate = useNavigate();
  const { addToast } = useToast();

  // Form State
  const [targetUrl, setTargetUrl] = useState('');
  const [selectedProgramId, setSelectedProgramId] = useState('');
  const [programs, setPrograms] = useState([]);
  const [apiError, setApiError] = useState(null);

  // Scope Validation State
  const [validatingScope, setValidatingScope] = useState(false);
  const [validatedTargetUrl, setValidatedTargetUrl] = useState(null);
  const [scopeDecision, setScopeDecision] = useState(null);

  // Authorization State
  const [authorizedBy, setAuthorizedBy] = useState('lead_security_operator');
  const [authReference, setAuthReference] = useState('');
  const [durationDays, setDurationDays] = useState(30);

  // Assessment Configuration
  const [assessmentMode, setAssessmentMode] = useState('CONTROLLED'); // Default: 'CONTROLLED'
  const [mode, setMode] = useState('SAFE_SCAN');
  const [campaignBudget, setCampaignBudget] = useState(500);
  const [targetBudget, setTargetBudget] = useState(100);
  const [checkBudget, setCheckBudget] = useState(20);
  const [maxConcurrency, setMaxConcurrency] = useState(5);
  const [operatorConfirmed, setOperatorConfirmed] = useState(false);
  const [selectedReconCapabilities, setSelectedReconCapabilities] = useState([]);

  // Launching state
  const [starting, setStarting] = useState(false);

  const isProduction = assessmentMode === 'PRODUCTION_AUTHORIZED';
  const isReconOnly = mode === 'RECON_ONLY';
  const confirmationText =
    'I confirm this concrete target is authorized under the selected bug-bounty program and I understand this assessment will perform real requests.';

  async function loadPrograms() {
    setApiError(null);
    try {
      const res = await getPrograms();
      const list = res.data?.data || res.data || [];
      const validList = Array.isArray(list) ? list : [];
      setPrograms(validList);
      if (validList.length > 0) {
        setSelectedProgramId(validList[0].id);
      }
    } catch (err) {
      console.error('Error fetching programs:', err);
      const errorMsg =
        err.response?.data?.error?.message ||
        err.response?.data?.detail ||
        err.message ||
        'Failed to load authorized scope programs.';
      setApiError(errorMsg);
    }
  }

  useEffect(() => {
    loadPrograms();
  }, []);

  const selectedProgram = programs.find((p) => p.id === selectedProgramId);
  const inScopeRules = normalizeScopeRules(selectedProgram?.scope);

  const handleAssessmentModeChange = (newMode) => {
    setAssessmentMode(newMode);
    if (newMode === 'PRODUCTION_AUTHORIZED') {
      if (mode === 'FULL_AUTHORIZED_SCAN') {
        setMode('SAFE_SCAN');
      }
    }
  };

  async function handleValidateScope() {
    const cleanUrl = targetUrl.trim();
    if (!cleanUrl || !selectedProgramId) {
      addToast({
        title: 'Missing Fields',
        message: 'Please enter a target URL and select an authorized program.',
        type: 'warning',
      });
      return;
    }

    // 1. Frontend validation: Ensure target URL is concrete HTTP/HTTPS and not a wildcard
    const urlCheck = validateConcreteTargetUrl(cleanUrl);
    if (!urlCheck.valid) {
      addToast({
        title: 'Invalid Target URL',
        message: urlCheck.error,
        type: 'warning',
      });
      setValidatedTargetUrl(null);
      setScopeDecision({
        allowed: false,
        status: 'INVALID',
        reason: urlCheck.error,
        asset: cleanUrl,
      });
      return;
    }

    try {
      setValidatingScope(true);
      setScopeDecision(null);
      setValidatedTargetUrl(null);

      // 2. Call backend validation endpoint with concrete target URL
      const res = await validateTargetScope(selectedProgramId, cleanUrl);
      const rawDecision = res.data?.data || res.data;
      const decision = {
        allowed: Boolean(rawDecision?.allowed),
        status: String(rawDecision?.status || (rawDecision?.allowed ? 'IN_SCOPE' : 'OUT_OF_SCOPE')),
        reason: normalizeReason(rawDecision?.reason),
        matched_rule: normalizeMatchedRule(rawDecision?.matched_rule),
        asset: cleanUrl,
      };
      setScopeDecision(decision);

      if (decision.allowed) {
        setValidatedTargetUrl(cleanUrl);
      }
    } catch (err) {
      const errData = err.response?.data?.error || err.response?.data;
      const errorMsg =
        errData?.message ||
        err.response?.data?.detail ||
        err.message ||
        'Could not validate scope with backend.';
      addToast({
        title: 'Scope Validation Failed',
        message: errorMsg,
        type: 'error',
      });
    } finally {
      setValidatingScope(false);
    }
  }

  async function handleStartAssessment(e) {
    e?.preventDefault();
    const cleanUrl = targetUrl.trim();

    if (!scopeDecision?.allowed || validatedTargetUrl !== cleanUrl) {
      addToast({
        title: 'Scope Gating Block',
        message: 'Target is not validated as in-scope. Please validate the target URL first.',
        type: 'error',
      });
      return;
    }

    const urlCheck = validateConcreteTargetUrl(cleanUrl);
    if (!urlCheck.valid) {
      addToast({
        title: 'Invalid Target URL',
        message: urlCheck.error,
        type: 'error',
      });
      return;
    }

    if (isProduction && !operatorConfirmed) {
      addToast({
        title: 'Confirmation Required',
        message: 'Please check the operator confirmation box before launching a production assessment.',
        type: 'warning',
      });
      return;
    }

    if (!authReference.trim()) {
      addToast({
        title: 'Authorization Reference Required',
        message: 'Enter the client ticket, contract, or other written scope reference before creating the campaign.',
        type: 'warning',
      });
      return;
    }

    try {
      setStarting(true);
      const targetHostname = urlCheck.host || cleanUrl;

      // 1. Create Campaign in DRAFT with exact validated concrete target
      const createRes = await createCampaign({
        name: isReconOnly ? `Recon: ${targetHostname}` : isProduction ? `Production: ${targetHostname}` : `Assessment: ${targetHostname}`,
        target_url: cleanUrl,
        mode: isReconOnly ? 'RECON_ONLY' : isProduction ? 'SAFE_SCAN' : mode,
        program_id: selectedProgramId,
        campaign_budget: isReconOnly ? 100 : isProduction ? 10 : Math.max(1, parseInt(campaignBudget, 10) || 500),
        target_budget: isReconOnly ? 100 : isProduction ? 10 : Math.max(1, parseInt(targetBudget, 10) || 100),
        check_budget: isReconOnly ? 1 : isProduction ? 5 : Math.max(1, parseInt(checkBudget, 10) || 20),
        max_concurrency: isReconOnly || isProduction ? 1 : Math.max(1, parseInt(maxConcurrency, 10) || 5),
        rate_limit_rps: isReconOnly || isProduction ? 2 : 10,
        in_scope_assets: [cleanUrl],
        selected_recon_capabilities: selectedReconCapabilities,
      });

      const campaignId = createRes.data?.data?.campaign_id || createRes.data?.data?.id;

      // 2. Authorize Campaign
      await authorizeCampaign(campaignId, {
        authorized_by: authorizedBy || 'lead_security_operator',
        authorization_type: isProduction ? 'bug_bounty_program_authorization' : 'explicit_scope_consent',
        authorization_reference: authReference.trim(),
        duration_days: Math.max(1, parseInt(durationDays, 10) || 30),
      });

      // 3. Start Execution
      await startCampaign(campaignId);

      addToast({
        title: isReconOnly ? 'Recon-Only Campaign Started' : isProduction ? 'Authorized Assessment Launched' : 'Assessment Started',
        message: `Campaign ${campaignId?.slice(0, 8)} launched in ${isReconOnly ? 'RECON_ONLY' : isProduction ? 'PRODUCTION_AUTHORIZED' : mode} mode.`,
        type: 'success',
      });

      navigate(`/campaigns?id=${campaignId}`);
    } catch (err) {
      const errData = err.response?.data?.error || err.response?.data;
      const errorCode = errData?.code;
      let errorMsg =
        errData?.message ||
        err.response?.data?.detail ||
        err.message ||
        'Failed to start assessment.';

      if (errorCode === 'WILDCARD_TARGET_NOT_ALLOWED') {
        errorMsg =
          'Wildcard scope rules cannot be used as assessment targets. Enter a concrete HTTP/HTTPS target URL.';
      } else if (errorCode === 'OUT_OF_SCOPE') {
        errorMsg = 'Target is not authorized by the selected program.';
      } else if (errorCode === 'INVALID_TARGET_URL') {
        errorMsg =
          'Enter a complete HTTP/HTTPS target URL, for example https://example.com.';
      }

      addToast({
        title: 'Launch Failed',
        message: errorMsg,
        type: 'error',
      });
    } finally {
      setStarting(false);
    }
  }

  const isScopeValidated =
    scopeDecision?.allowed === true &&
    validatedTargetUrl === targetUrl.trim() &&
    targetUrl.trim() !== '';

  const hasReadinessData = Boolean(
    isScopeValidated &&
    targetUrl.trim() &&
    selectedProgram &&
    scopeDecision
  );

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Page Title */}
      <div className="pb-2 border-b border-border">
        <h1 className="text-xl font-bold tracking-tight text-text-primary">
          New Security Assessment
        </h1>
        <p className="text-xs text-text-secondary mt-0.5">
          Step-by-step target specification, scope pre-flight validation, and authorized execution.
        </p>
      </div>

      {/* Explicit API Error Banner */}
      {apiError && (
        <Alert
          variant="destructive"
          title="API Error: Scope Programs Unavailable"
          className="mb-4"
        >
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <span>{apiError}</span>
            <Button
              variant="outline"
              size="xs"
              onClick={loadPrograms}
              className="mt-1 sm:mt-0 flex items-center gap-1 text-xs"
            >
              <RefreshCw className="w-3 h-3" aria-hidden="true" focusable="false" />
              <span>Retry Connection</span>
            </Button>
          </div>
        </Alert>
      )}

      <div className="space-y-6">
        {/* Step 1: Target & Program Specification */}
        <Card className="p-5 bg-surface border-border space-y-4">
          <div className="flex items-center gap-2 pb-2 border-b border-border">
            <div className="w-5 h-5 rounded-full bg-accent/20 text-accent flex items-center justify-center text-xs font-bold font-mono">
              1
            </div>
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
              Target URL & Scope Program
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <Input
                label="Target Root URL"
                placeholder="https://example-shop.myshopify.com"
                value={targetUrl}
                onChange={(e) => {
                  setTargetUrl(e.target.value);
                  setValidatedTargetUrl(null);
                  setScopeDecision(null);
                }}
                className="text-xs font-mono"
                required
              />
              <p className="text-[11px] text-text-muted mt-1">
                Enter the specific concrete HTTP or HTTPS URL to scan. Wildcards are not allowed as targets.
              </p>
            </div>

            <div>
              <label htmlFor="authorized-program-select" className="block text-xs font-medium text-text-secondary mb-1.5">
                Authorized Scope Program
              </label>
              <select
                id="authorized-program-select"
                aria-label="Authorized Scope Program"
                value={selectedProgramId}
                onChange={(e) => {
                  setSelectedProgramId(e.target.value);
                  setValidatedTargetUrl(null);
                  setScopeDecision(null);
                }}
                className="w-full h-9 rounded bg-surface-2 border border-border px-3 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              >
                {programs.map((p) => {
                  const ruleCount = normalizeScopeRules(p.scope).length;
                  return (
                    <option key={p.id} value={p.id}>
                      {p.name} ({ruleCount} in-scope rules)
                    </option>
                  );
                })}
              </select>
              <p className="text-[11px] text-text-muted mt-1">
                Select the pre-approved bug bounty or organizational scope policy.
              </p>
            </div>
          </div>

          {/* Authorized Scope Rules Metadata Display */}
          {selectedProgram && (
            <div className="p-3.5 rounded bg-surface-2/60 border border-border/80 space-y-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-text-secondary">
                <ShieldCheck className="w-4 h-4 text-accent" aria-hidden="true" focusable="false" />
                <span>Authorized Scope Rules ({selectedProgram.name || 'Program'})</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {inScopeRules.length > 0 ? (
                  inScopeRules.map((rule, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded bg-surface border border-border text-[11px] font-mono text-text-primary flex items-center gap-1"
                    >
                      <Globe className="w-3 h-3 text-text-muted" aria-hidden="true" focusable="false" />
                      <span>{rule}</span>
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-text-muted italic">No scope rules defined for this program.</span>
                )}
              </div>
              <p className="text-[10px] text-text-muted leading-tight">
                * Scope wildcard patterns (e.g. *.shopify.com) define authorization boundaries. The Target Root URL above must be a concrete host within this scope.
              </p>
            </div>
          )}

          {/* Scope Validation Action */}
          <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="text-xs text-text-muted">
              Safety Control: Pre-flight scope verification must pass before launch.
            </div>
            <Button
              variant="secondary"
              size="sm"
              loading={validatingScope}
              disabled={!targetUrl.trim() || !selectedProgramId}
              onClick={handleValidateScope}
            >
              Validate Scope
            </Button>
          </div>

          {/* High-Visibility Scope Status Banner */}
          {scopeDecision && (
            <div
              className={`p-4 rounded border text-xs ${
                scopeDecision.allowed
                  ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-800 text-rose-300'
              }`}
            >
              <div className="flex items-center gap-2 font-bold text-sm">
                {scopeDecision.allowed ? (
                  <>
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" aria-hidden="true" focusable="false" />
                    <span>● SCOPE VALIDATED</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-5 h-5 text-rose-400" aria-hidden="true" focusable="false" />
                    <span>● {scopeDecision.status === 'INVALID' ? 'INVALID TARGET' : 'OUT OF SCOPE — BLOCKED'}</span>
                  </>
                )}
              </div>
              <p className="mt-1 font-mono text-[11px] opacity-90 leading-relaxed">
                {scopeDecision.allowed
                  ? 'Target is explicitly authorized for this assessment.'
                  : 'Request blocked at boundary. Zero target-network bytes will be transmitted.'}
              </p>
              <div className="mt-2 text-[10px] font-mono text-text-muted border-t border-border/40 pt-1.5 space-y-0.5">
                <div>
                  <span className="font-semibold text-text-secondary">Target:</span> {targetUrl.trim()}
                </div>
                {scopeDecision.matched_rule && (
                  <div>
                    <span className="font-semibold text-text-secondary">Authorized by:</span>{' '}
                    <span>{scopeDecision.matched_rule}</span>
                  </div>
                )}
                <div>
                  <span className="font-semibold text-text-secondary">Status:</span> {scopeDecision.status} &bull;{' '}
                  <span className="font-semibold text-text-secondary">Reason:</span> {scopeDecision.reason}
                </div>
              </div>
            </div>
          )}
        </Card>

        {/* Step 2: Operator Authorization Record */}
        <Card className={`p-5 bg-surface border-border space-y-4 ${!isScopeValidated ? 'opacity-50 pointer-events-none' : ''}`}>
          <div className="flex items-center gap-2 pb-2 border-b border-border">
            <div className="w-5 h-5 rounded-full bg-accent/20 text-accent flex items-center justify-center text-xs font-bold font-mono">
              2
            </div>
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
              Operator Authorization Gating
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Input
              label="Authorized By"
              value={authorizedBy}
              onChange={(e) => setAuthorizedBy(e.target.value)}
              className="text-xs"
              required
            />
            <Input
              label="Ticket / Contract Reference"
              value={authReference}
              onChange={(e) => setAuthReference(e.target.value)}
              className="text-xs"
              required
            />
            <Input
              label="Auth Duration (Days)"
              type="number"
              value={durationDays}
              onChange={(e) => setDurationDays(Math.max(1, parseInt(e.target.value, 10) || 1))}
              className="text-xs font-mono"
              min={1}
              max={365}
            />
          </div>
        </Card>

        {/* Step 3: Execution Engine Configuration */}
        <Card className={`p-5 bg-surface border-border space-y-4 ${!isScopeValidated ? 'opacity-50 pointer-events-none' : ''}`}>
          <div className="flex items-center gap-2 pb-2 border-b border-border">
            <div className="w-5 h-5 rounded-full bg-accent/20 text-accent flex items-center justify-center text-xs font-bold font-mono">
              3
            </div>
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
              Assessment Configuration
            </h2>
          </div>

          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label htmlFor="assessment-mode-select" className="block text-xs font-medium text-text-secondary mb-1.5">
                  Assessment Mode
                </label>
                <select
                  id="assessment-mode-select"
                  aria-label="Assessment Mode"
                  value={assessmentMode}
                  onChange={(e) => handleAssessmentModeChange(e.target.value)}
                  className="w-full h-9 rounded bg-surface-2 border border-border px-3 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent font-semibold"
                >
                  <option value="CONTROLLED">CONTROLLED (Operator Controlled Environment)</option>
                  <option value="PRODUCTION_AUTHORIZED">PRODUCTION_AUTHORIZED (Conservative Bug-Bounty Limits)</option>
                </select>
                <p className="text-[11px] text-text-muted mt-1">
                  {isProduction
                    ? 'Production mode locks conservative rate and budget limits server-side.'
                    : 'Controlled mode allows custom concurrency and budget allocations.'}
                </p>
              </div>

              <div>
                <label htmlFor="scan-profile-select" className="block text-xs font-medium text-text-secondary mb-1.5">
                  Scan Profile
                </label>
                <select
                  id="scan-profile-select"
                  aria-label="Scan Profile"
                  value={mode}
                  onChange={(e) => setMode(e.target.value)}
                  className="w-full h-9 rounded bg-surface-2 border border-border px-3 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
                >
                  <option value="SAFE_SCAN">SAFE_SCAN (Safe & Non-Destructive)</option>
                  <option value="PLAN_ONLY">PLAN_ONLY (Recon & Graph Only)</option>
                  <option value="RECON_ONLY">RECON_ONLY (Reconnaissance Only)</option>
                  {!isProduction && <option value="FULL_AUTHORIZED_SCAN">FULL_AUTHORIZED_SCAN (All 77 Checks)</option>}
                </select>
              </div>
            </div>

            <div className="rounded border border-border p-3 space-y-2">
              <p className="text-xs font-semibold text-text-primary">Optional active recon tools (off by default)</p>
              <p className="text-[11px] text-text-muted">Nmap service discovery and Gobuster path discovery run only when selected. They stay scope checked and use bounded profiles.</p>
              <div className="flex flex-wrap gap-4 text-xs">
                {[['service_discovery', 'Nmap service discovery'], ['content_discovery', 'Gobuster path discovery']].map(([capability, label]) => (
                  <label key={capability} className="inline-flex items-center gap-2 text-text-secondary">
                    <input
                      type="checkbox"
                      checked={selectedReconCapabilities.includes(capability)}
                      onChange={(event) => setSelectedReconCapabilities((current) => event.target.checked
                        ? [...new Set([...current, capability])]
                        : current.filter((item) => item !== capability))}
                    />
                    {label}
                  </label>
                ))}
              </div>
            </div>

            {isProduction || isReconOnly ? (
              <div className="p-3.5 rounded bg-amber-950/20 border border-amber-800/40 text-xs space-y-2">
                <div className="flex items-center gap-2 font-semibold text-amber-300 text-xs">
                  <Lock className="w-3.5 h-3.5" aria-hidden="true" focusable="false" />
                  <span>{isReconOnly ? 'RECON-ONLY PROFILE (BOUNDED)' : 'CONSERVATIVE PRODUCTION PROFILE (LOCKED BY SERVER)'}</span>
                </div>
                {isReconOnly && <p className="text-[11px] text-text-secondary">The campaign runs the shared scoped recon pipeline. Vulnerability checks are not launched. Nmap and Gobuster run only if selected above.</p>}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[11px]">
                  <div className="p-2 rounded bg-surface border border-border/60">
                    <span className="text-text-muted block text-[10px]">BUDGET</span>
                    <span className="text-amber-400 font-bold">{isReconOnly ? '100 Max Requests' : '10 Max Requests'}</span>
                  </div>
                  <div className="p-2 rounded bg-surface border border-border/60">
                    <span className="text-text-muted block text-[10px]">CONCURRENCY</span>
                    <span className="text-amber-400 font-bold">1 Worker</span>
                  </div>
                  <div className="p-2 rounded bg-surface border border-border/60">
                    <span className="text-text-muted block text-[10px]">RATE LIMIT</span>
                    <span className="text-amber-400 font-bold">2 RPS</span>
                  </div>
                  <div className="p-2 rounded bg-surface border border-border/60">
                    <span className="text-text-muted block text-[10px]">HTTP METHODS</span>
                    <span className="text-amber-400 font-bold">GET/HEAD/OPTIONS</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <Input
                  label="Campaign Budget (Max Reqs)"
                  type="number"
                  value={campaignBudget}
                  onChange={(e) => setCampaignBudget(Math.max(1, parseInt(e.target.value, 10) || 1))}
                  className="text-xs font-mono"
                  min={1}
                />
                <Input
                  label="Per-Target Budget"
                  type="number"
                  value={targetBudget}
                  onChange={(e) => setTargetBudget(Math.max(1, parseInt(e.target.value, 10) || 1))}
                  className="text-xs font-mono"
                  min={1}
                />
                <Input
                  label="Per-Check Budget"
                  type="number"
                  value={checkBudget}
                  onChange={(e) => setCheckBudget(Math.max(1, parseInt(e.target.value, 10) || 1))}
                  className="text-xs font-mono"
                  min={1}
                />
                <Input
                  label="Max Concurrency"
                  type="number"
                  value={maxConcurrency}
                  onChange={(e) => setMaxConcurrency(Math.min(20, Math.max(1, parseInt(e.target.value, 10) || 1)))}
                  className="text-xs font-mono"
                  min={1}
                  max={20}
                />
              </div>
            )}
          </div>
        </Card>

        {/* Step 4: Pre-Flight Execution Checklist */}
        {isScopeValidated && (
          <ErrorBoundary
            fallback={
              <Card className="p-5 bg-surface border-border">
                <div
                  data-testid="preflight-unavailable"
                  className="p-4 rounded border border-border bg-surface-2/60 text-xs text-text-muted italic flex items-center gap-2"
                >
                  <ShieldCheck className="w-4 h-4 text-text-muted" aria-hidden="true" focusable="false" />
                  <span>Pre-flight information unavailable</span>
                </div>
              </Card>
            }
          >
            {hasReadinessData ? (
              <Card className="p-5 bg-surface border-border space-y-4">
                <div className="flex items-center justify-between pb-2 border-b border-border">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-accent" aria-hidden="true" focusable="false" />
                    <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                      {isReconOnly
                        ? 'RECON-ONLY CAMPAIGN — PRE-FLIGHT READINESS'
                        : isProduction
                          ? 'PRODUCTION AUTHORIZED ASSESSMENT — PRE-FLIGHT READINESS'
                          : 'CONTROLLED ASSESSMENT — PRE-FLIGHT READINESS'}
                    </h2>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent/10 text-accent font-semibold">
                    MODE: {isReconOnly ? 'RECON_ONLY' : isProduction ? 'PRODUCTION_AUTHORIZED' : mode}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 text-xs">
                  <div className="p-2.5 rounded bg-surface-2/60 border border-emerald-900/40 text-text-primary space-y-0.5">
                    <div className="text-[10px] text-text-muted uppercase">Target URL</div>
                    <div className="font-mono text-[11px] text-emerald-400 truncate">{targetUrl.trim()}</div>
                  </div>

                  <div className="p-2.5 rounded bg-surface-2/60 border border-emerald-900/40 text-text-primary space-y-0.5">
                    <div className="text-[10px] text-text-muted uppercase">Program & Policy</div>
                    <div className="font-mono text-[11px] text-emerald-400 truncate">
                      {selectedProgram?.name || 'Authorized Program'}{' '}
                      {selectedProgram?.policy_url ? `(${String(selectedProgram.policy_url)})` : ''}
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-surface-2/60 border border-emerald-900/40 text-text-primary space-y-0.5">
                    <div className="text-[10px] text-text-muted uppercase">Scope Decision</div>
                    <div className="font-mono text-[11px] text-emerald-400 font-semibold flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" focusable="false" />
                      <span>IN SCOPE (PASS)</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-surface-2/60 border border-emerald-900/40 text-text-primary space-y-0.5">
                    <div className="text-[10px] text-text-muted uppercase">Authorization</div>
                    <div className="font-mono text-[11px] text-emerald-400 font-semibold flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" focusable="false" />
                      <span>PASS ({durationDays}d Active)</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-surface-2/60 border border-emerald-900/40 text-text-primary space-y-0.5">
                    <div className="text-[10px] text-text-muted uppercase">Destination Safety</div>
                    <div className="font-mono text-[11px] text-emerald-400 font-semibold flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" focusable="false" />
                      <span>PASS (Metadata / SSRF Blocked)</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-surface-2/60 border border-emerald-900/40 text-text-primary space-y-0.5">
                    <div className="text-[10px] text-text-muted uppercase">Request Budget / Limit</div>
                    <div className="font-mono text-[11px] text-emerald-400 font-semibold">
                      {isProduction ? '10 Max Requests (LOCKED)' : `${campaignBudget} Max Requests`}
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-surface-2/60 border border-emerald-900/40 text-text-primary space-y-0.5">
                    <div className="text-[10px] text-text-muted uppercase">Concurrency & Rate</div>
                    <div className="font-mono text-[11px] text-emerald-400 font-semibold">
                      {isProduction ? '1 Worker @ 2 RPS (LOCKED)' : `${maxConcurrency} Workers`}
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-surface-2/60 border border-emerald-900/40 text-text-primary space-y-0.5">
                    <div className="text-[10px] text-text-muted uppercase">Allowed HTTP Methods</div>
                    <div className="font-mono text-[11px] text-emerald-400 font-semibold">
                      {isProduction ? 'GET / HEAD / OPTIONS ONLY' : 'Standard Methods'}
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-surface-2/60 border border-emerald-900/40 text-text-primary space-y-0.5">
                    <div className="text-[10px] text-text-muted uppercase">RequestEngine Boundary</div>
                    <div className="font-mono text-[11px] text-emerald-400 font-semibold flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" focusable="false" />
                      <span>REQUIRED (Central Transport)</span>
                    </div>
                  </div>
                </div>

                {/* Operator confirmation requirement for Production mode */}
                {isProduction && (
                  <label className="flex items-start gap-2.5 p-3 rounded bg-amber-950/20 border border-amber-800/40 cursor-pointer text-xs text-amber-200">
                    <input
                      type="checkbox"
                      checked={operatorConfirmed}
                      onChange={(e) => setOperatorConfirmed(e.target.checked)}
                      className="mt-0.5 rounded border-amber-600 text-amber-500 focus:ring-amber-400"
                    />
                    <span className="font-mono text-[11px] leading-relaxed">
                      {confirmationText}
                    </span>
                  </label>
                )}

                <div className="p-3 rounded bg-accent/5 border border-accent/20 text-xs text-text-secondary">
                  <span className="font-semibold text-accent">Operator Certification:</span> By launching, you certify that this assessment will execute strictly against the displayed concrete target URL (<code className="text-text-primary">{targetUrl.trim()}</code>) using authorized, non-destructive checks within server-enforced boundaries.
                </div>
              </Card>
            ) : (
              <Card className="p-5 bg-surface border-border">
                <div
                  data-testid="preflight-unavailable"
                  className="p-4 rounded border border-border bg-surface-2/60 text-xs text-text-muted italic flex items-center gap-2"
                >
                  <ShieldCheck className="w-4 h-4 text-text-muted" aria-hidden="true" focusable="false" />
                  <span>Pre-flight information unavailable</span>
                </div>
              </Card>
            )}
          </ErrorBoundary>
        )}

        {/* Launch Trigger */}
        <div className="flex items-center justify-between p-4 rounded bg-surface border border-border">
          <div className="text-xs text-text-secondary">
            {isScopeValidated ? (
              <span className="text-emerald-400 font-medium flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" aria-hidden="true" focusable="false" />
                <span>Ready to dispatch assessment for {targetUrl.trim()}.</span>
              </span>
            ) : !targetUrl.trim() ? (
              <span className="text-amber-400 font-medium flex items-center gap-1.5">
                <Lock className="w-4 h-4" aria-hidden="true" focusable="false" />
                <span>WAITING FOR TARGET — Supply a concrete authorized target URL.</span>
              </span>
            ) : (
              <span className="text-text-muted flex items-center gap-1.5">
                <Lock className="w-4 h-4" aria-hidden="true" focusable="false" />
                <span>Scope validation required before launch.</span>
              </span>
            )}
          </div>

          <Button
            variant="primary"
            size="md"
            className="flex items-center gap-2 font-semibold px-6 shadow-sm"
            disabled={!isScopeValidated || starting || (isProduction && !operatorConfirmed)}
            loading={starting}
            onClick={handleStartAssessment}
          >
            <Play className="w-4 h-4" aria-hidden="true" focusable="false" />
            <span>{isReconOnly ? 'Launch Recon-Only Campaign' : isProduction ? 'Launch Authorized Assessment' : 'Launch Controlled Assessment'}</span>
          </Button>
        </div>
      </div>
    </div>
  );
}
