import { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Play,
  Zap,
  Globe,
  RefreshCw,
} from 'lucide-react';
import {
  getCampaignHypotheses,
  getCampaignVerificationBudget,
  approveRealVerification,
  executeRealVerification,
} from '../lib/api';
import { useToast } from '../hooks/useToast';

export default function RealWorldValidationQueue({ campaignId, targetUrl, onVerificationComplete }) {
  const { addToast } = useToast();
  const [hypotheses, setHypotheses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [budgetInfo, setBudgetInfo] = useState({ remaining_budget: 10, budget_cap: 10, requests_used: 0 });
  const [selectedHypothesis, setSelectedHypothesis] = useState(null);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [confirmedLiveDispatch, setConfirmedLiveDispatch] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);
  const [rejectionReason, setRejectionReason] = useState('');
  const [showRejectModal, setShowRejectModal] = useState(false);

  const fetchHypotheses = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getCampaignHypotheses(campaignId);
      if (res.data?.success) {
        setHypotheses(res.data.data.hypotheses || []);
      }

      const budgetRes = await getCampaignVerificationBudget(campaignId);
      if (budgetRes.data?.success) {
        setBudgetInfo(budgetRes.data.data);
      }
    } catch (err) {
      console.error('Error fetching hypotheses for real validation:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to load hypotheses');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (campaignId) {
      fetchHypotheses();
    }
  }, [campaignId]);

  const handleApproveAndOpenModal = async (hyp) => {
    try {
      setSelectedHypothesis(hyp);
      setShowConfirmModal(true);
      setConfirmedLiveDispatch(false);
      setExecutionResult(null);
    } catch (err) {
      addToast({ title: 'Approval error', message: err.response?.data?.detail || err.message, variant: 'error' });
    }
  };

  const handleLogDecision = async (hypothesisId, decision, rationale = '') => {
    try {
      await approveRealVerification(campaignId, hypothesisId, {
        decision,
        target: targetUrl,
        rationale,
        acknowledgement: decision === 'APPROVE' ? 'I understand that this action will send a real request to the authorized target.' : undefined,
      });
      fetchHypotheses();
      setShowRejectModal(false);
      setRejectionReason('');
    } catch (err) {
      addToast({ title: 'Decision error', message: err.response?.data?.detail || err.message, variant: 'error' });
    }
  };

  const executeLiveVerification = async () => {
    if (!selectedHypothesis || !confirmedLiveDispatch) return;
    try {
      setExecuting(true);
      setExecutionResult(null);

      // Step 1: Ensure approval is recorded
      await approveRealVerification(campaignId, selectedHypothesis.hypothesis_id, {
        decision: 'APPROVE',
        target: targetUrl,
        strategy_id: selectedHypothesis.strategy_id,
        acknowledgement: 'I understand that this action will send a real request to the authorized target.',
      });

      // Step 2: Dispatch real execution
      const res = await executeRealVerification(campaignId, selectedHypothesis.hypothesis_id, {
        strategy_id: selectedHypothesis.strategy_id,
        execution_mode: 'PRODUCTION',
      });

      if (res.data?.success) {
        setExecutionResult(res.data.data);
        fetchHypotheses();
        if (onVerificationComplete) {
          onVerificationComplete(res.data.data);
        }
      }
    } catch (err) {
      console.error('Live execution error:', err);
      addToast({ title: 'Verification failed', message: err.response?.data?.detail || err.message, variant: 'error' });
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Real-World Mode Warning Banner */}
      <div className="p-4 rounded-lg bg-emerald-950/40 border border-emerald-500/40 flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/20 text-emerald-400 mt-0.5 animate-pulse">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-sm text-emerald-400 tracking-wider">
                LIVE AUTHORIZED TARGET MODE (PHASE 22)
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                REAL HTTP
              </span>
            </div>
            <p className="text-xs text-emerald-200/80 mt-1 max-w-2xl">
              Target: <span className="font-mono text-white font-semibold">{targetUrl}</span>. Approved verifications dispatch real HTTP requests through RequestEngine. No simulated responses.
            </p>
          </div>
        </div>

        <button
          onClick={fetchHypotheses}
          disabled={loading}
          className="px-3 py-1.5 rounded text-xs font-medium bg-surface hover:bg-surface-2 border border-border text-text-secondary flex items-center gap-1.5"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Safety Invariants Status Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 rounded-lg bg-surface border border-border">
        <div>
          <div className="text-[10px] uppercase font-mono text-text-muted">Verification Budget</div>
          <div className="text-base font-bold font-mono text-text-primary mt-0.5">
            {budgetInfo.remaining_budget} / {budgetInfo.budget_cap || 10}
          </div>
          <div className="text-[10px] text-text-muted mt-0.5">Max 10 reqs/campaign</div>
        </div>
        <div>
          <div className="text-[10px] uppercase font-mono text-text-muted">Concurrency Limit</div>
          <div className="text-base font-bold font-mono text-emerald-400 mt-0.5">1 Worker</div>
          <div className="text-[10px] text-text-muted mt-0.5">Single-thread locked</div>
        </div>
        <div>
          <div className="text-[10px] uppercase font-mono text-text-muted">Rate Ceiling</div>
          <div className="text-base font-bold font-mono text-emerald-400 mt-0.5">2.0 RPS</div>
          <div className="text-[10px] text-text-muted mt-0.5">Token bucket enforced</div>
        </div>
        <div>
          <div className="text-[10px] uppercase font-mono text-text-muted">Allowed Methods</div>
          <div className="text-base font-bold font-mono text-text-primary mt-0.5">GET, HEAD, OPTIONS</div>
          <div className="text-[10px] text-text-muted mt-0.5">Zero mutations permitted</div>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Hypotheses Queue Table */}
      <div className="rounded-lg border border-border bg-surface overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
              <Zap className="w-4 h-4 text-emerald-400" />
              Real-World Validation Queue ({hypotheses.length})
            </h3>
            <p className="text-xs text-text-muted mt-0.5">
              Operator-gated verification hypotheses requiring explicit authorization.
            </p>
          </div>
        </div>

        {hypotheses.length === 0 ? (
          <div className="p-8 text-center text-text-muted text-xs">
            No candidate hypotheses generated for this campaign.
          </div>
        ) : (
          <div className="divide-y divide-border">
            {hypotheses.map((hyp) => {
              const isApproved = hyp.authorization_status === 'APPROVE';
              const isRejected = hyp.authorization_status === 'REJECT';

              return (
                <div key={hyp.hypothesis_id} className="p-4 hover:bg-surface-2/40 transition-colors space-y-3">
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-accent">
                          {hyp.vuln_type}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-surface-2 border border-border text-text-secondary">
                          {hyp.endpoint}
                        </span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                            isApproved
                              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              : isRejected
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                              : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          }`}
                        >
                          {hyp.authorization_status || 'HUMAN_REVIEW_REQUIRED'}
                        </span>
                      </div>
                      <p className="text-xs text-text-secondary leading-relaxed">
                        {hyp.rationale || 'Vulnerability hypothesis awaiting real-world verification.'}
                      </p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleApproveAndOpenModal(hyp)}
                        disabled={budgetInfo.remaining_budget <= 0}
                        className="px-3 py-1.5 rounded text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1.5 shadow transition-colors disabled:opacity-50"
                      >
                        <Play className="w-3.5 h-3.5 fill-white" />
                        Approve & Dispatch
                      </button>
                      <button
                        onClick={() => {
                          setSelectedHypothesis(hyp);
                          setShowRejectModal(true);
                        }}
                        className="px-2.5 py-1.5 rounded text-xs font-medium bg-surface hover:bg-surface-2 border border-border text-text-muted hover:text-rose-400 transition-colors"
                      >
                        Reject
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono text-text-muted bg-surface-2/60 p-2.5 rounded border border-border/50">
                    <div>
                      <span className="text-text-secondary font-semibold">Strategy:</span> {hyp.strategy_id}
                    </div>
                    <div>
                      <span className="text-text-secondary font-semibold">Cost:</span> {hyp.estimated_requests || 1} req (GET/HEAD)
                    </div>
                    <div className="sm:col-span-2">
                      <span className="text-text-secondary font-semibold">Expected Proof:</span> {hyp.expected_evidence_type || 'HTTP response differential'}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Confirmation & Live Dispatch Modal */}
      {showConfirmModal && selectedHypothesis && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="max-w-md w-full rounded-xl bg-surface border border-emerald-500/50 shadow-2xl p-6 space-y-4">
            <div className="flex items-center gap-3 text-emerald-400">
              <ShieldAlert className="w-6 h-6 shrink-0" />
              <h3 className="font-bold text-base text-white">Authorize Real HTTP Verification</h3>
            </div>

            <div className="p-3.5 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-xs text-emerald-200/90 leading-relaxed">
              <strong>THIS ACTION WILL SEND A REAL REQUEST TO THE AUTHORIZED TARGET.</strong>
              <div className="font-mono text-[11px] mt-1.5 text-white bg-black/40 p-2 rounded">
                Target: {targetUrl}
                <br />
                Endpoint: {selectedHypothesis.endpoint}
                <br />
                Method: GET (Bounded, Safe)
              </div>
            </div>

            <label className="flex items-start gap-2.5 text-xs text-text-secondary cursor-pointer">
              <input
                type="checkbox"
                checked={confirmedLiveDispatch}
                onChange={(e) => setConfirmedLiveDispatch(e.target.checked)}
                className="mt-0.5 rounded border-border text-emerald-500 focus:ring-emerald-500"
              />
              <span>
                I acknowledge and confirm this real HTTP verification request against the authorized target.
              </span>
            </label>

            {executionResult && (
              <div className="p-3 rounded bg-surface-2 border border-border text-xs space-y-1 font-mono">
                <div className="font-bold text-emerald-400">Verification Result: {executionResult.status}</div>
                <div className="text-[11px] text-text-muted">Verdict: {executionResult.correlation_verdict}</div>
                <div className="text-[11px] text-text-muted">{executionResult.result_details}</div>
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-border">
              <button
                onClick={() => setShowConfirmModal(false)}
                className="px-3 py-1.5 rounded text-xs font-medium text-text-secondary hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={executeLiveVerification}
                disabled={!confirmedLiveDispatch || executing}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1.5 shadow disabled:opacity-50"
              >
                {executing ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Executing Real Request...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-white" />
                    Confirm & Dispatch Real Request
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reject Modal */}
      {showRejectModal && selectedHypothesis && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="max-w-md w-full rounded-xl bg-surface border border-border shadow-2xl p-6 space-y-4">
            <h3 className="font-bold text-sm text-white">Reject Hypothesis</h3>
            <p className="text-xs text-text-muted">
              Rejecting will mark this hypothesis as invalid and prevent execution.
            </p>
            <textarea
              value={rejectionReason}
              onChange={(e) => setRejectionReason(e.target.value)}
              placeholder="Enter rationale for rejecting this hypothesis..."
              rows={3}
              className="w-full text-xs rounded border border-border bg-surface-2 p-2.5 text-white"
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowRejectModal(false)}
                className="px-3 py-1.5 rounded text-xs text-text-secondary"
              >
                Cancel
              </button>
              <button
                onClick={() => handleLogDecision(selectedHypothesis.hypothesis_id, 'REJECT', rejectionReason)}
                className="px-3 py-1.5 rounded text-xs bg-rose-600 hover:bg-rose-500 text-white font-semibold"
              >
                Confirm Rejection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
