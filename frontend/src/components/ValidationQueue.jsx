import { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Play,
  Lock,
  Activity,
} from 'lucide-react';
import { api } from '../lib/api';

export default function ValidationQueue({ campaignId, targetUrl, onVerificationComplete }) {
  const [hypotheses, setHypotheses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [budgetInfo, setBudgetInfo] = useState({ remaining_budget: 10, budget_cap: 10, requests_used: 0 });
  const [selectedHypothesis, setSelectedHypothesis] = useState(null);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [confirmedRisk, setConfirmedRisk] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);
  const [rejectionReason, setRejectionReason] = useState('');
  const [showRejectModal, setShowRejectModal] = useState(false);

  const fetchHypotheses = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get(`/api/campaigns/${campaignId}/hypotheses`);
      if (res.data?.success) {
        setHypotheses(res.data.data.hypotheses || []);
      }
      
      const budgetRes = await api.get(`/api/campaigns/${campaignId}/verification-budget`);
      if (budgetRes.data?.success) {
        setBudgetInfo(budgetRes.data.data);
      }
    } catch (err) {
      console.error('Error fetching hypotheses:', err);
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

  const handleDecision = async (hypothesisId, decision, reason = '') => {
    try {
      const res = await api.post(`/api/campaigns/${campaignId}/hypotheses/${hypothesisId}/decision`, {
        decision,
        reason,
      });
      if (res.data?.success) {
        fetchHypotheses();
        if (decision === 'APPROVE') {
          // Open execution modal
          const hyp = hypotheses.find((h) => h.hypothesis_id === hypothesisId);
          setSelectedHypothesis(hyp);
          setShowConfirmModal(true);
          setConfirmedRisk(false);
        }
      }
    } catch (err) {
      alert(`Decision error: ${err.response?.data?.detail || err.message}`);
    }
  };

  const executeVerification = async () => {
    if (!selectedHypothesis || !confirmedRisk) return;
    try {
      setExecuting(true);
      setExecutionResult(null);
      const res = await api.post(`/api/campaigns/${campaignId}/hypotheses/${selectedHypothesis.hypothesis_id}/verify`, {
        decision: 'APPROVE',
      });
      if (res.data?.success) {
        setExecutionResult(res.data.data);
        fetchHypotheses();
        if (onVerificationComplete) {
          onVerificationComplete(res.data.data);
        }
      }
    } catch (err) {
      alert(`Execution failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setExecuting(false);
    }
  };

  if (loading && hypotheses.length === 0) {
    return (
      <div className="p-8 text-center bg-slate-900/50 rounded-xl border border-slate-800 animate-pulse">
        <Activity className="w-8 h-8 text-cyan-400 mx-auto mb-3 animate-spin" />
        <p className="text-slate-400 font-medium">Generating Bounded Vulnerability Hypotheses...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Target & Budget Header */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg backdrop-blur">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400">Authorized Target</span>
            </div>
            <p className="text-lg font-mono font-bold text-slate-100">{targetUrl || 'No Target Bound'}</p>
          </div>

          <div className="flex items-center gap-6">
            <div className="text-right">
              <div className="text-xs text-slate-400 uppercase tracking-wider">Remaining Budget</div>
              <div className="text-2xl font-mono font-bold text-emerald-400">
                {budgetInfo.remaining_budget} <span className="text-xs text-slate-500 font-normal">/ {budgetInfo.budget_cap} reqs</span>
              </div>
            </div>

            <div className="text-right">
              <div className="text-xs text-slate-400 uppercase tracking-wider">Hypotheses</div>
              <div className="text-2xl font-mono font-bold text-cyan-400">{hypotheses.length}</div>
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/50 rounded-xl text-rose-300 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Hypotheses Queue */}
      <div className="space-y-4">
        {hypotheses.length === 0 ? (
          <div className="p-12 text-center bg-slate-900/30 rounded-xl border border-slate-800">
            <CheckCircle className="w-10 h-10 text-slate-600 mx-auto mb-3" />
            <h3 className="text-lg font-semibold text-slate-300">No Pending Hypotheses</h3>
            <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
              Surface inventory observations have been evaluated. No further bounded vulnerability hypotheses remain for this target.
            </p>
          </div>
        ) : (
          hypotheses.map((hyp) => (
            <div
              key={hyp.hypothesis_id}
              className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 transition-all hover:border-slate-700 shadow-md space-y-4"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1.5 flex-1 min-w-[280px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-2.5 py-0.5 text-xs font-bold rounded-md bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-mono">
                      {hyp.vulnerability_class}
                    </span>
                    <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-300 font-mono">
                      {hyp.method} {hyp.parameter ? `[param: ${hyp.parameter}]` : ''}
                    </span>
                    <span className="text-xs text-amber-400 bg-amber-950/40 border border-amber-800/40 px-2 py-0.5 rounded font-mono">
                      Cost: {hyp.estimated_requests} req
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      Conf: {(hyp.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <h4 className="text-base font-semibold text-slate-100">{hyp.hypothesis}</h4>
                  <p className="text-sm text-slate-400">{hyp.rationale}</p>
                </div>

                {/* Status Badge */}
                <div className="text-right">
                  <span
                    className={`px-3 py-1 text-xs font-bold rounded-full uppercase tracking-wider font-mono ${
                      hyp.status === 'VERIFIED'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : hyp.status === 'APPROVED'
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                        : hyp.status === 'REJECTED'
                        ? 'bg-rose-950 text-rose-400 border border-rose-800'
                        : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}
                  >
                    {hyp.status}
                  </span>
                </div>
              </div>

              {/* Expected Evidence & Strategy */}
              <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800/80 text-xs space-y-2 font-mono">
                <div className="text-slate-300">
                  <span className="text-slate-500 font-semibold">EXPECTED EVIDENCE: </span>
                  {hyp.expected_evidence}
                </div>
                <div className="text-slate-400">
                  <span className="text-slate-500 font-semibold">STRATEGY CONTRACT: </span>
                  {hyp.verification_strategy}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center justify-between pt-2 border-t border-slate-800/60 gap-2">
                <span className="text-xs text-amber-400/90 flex items-center gap-1 font-mono">
                  <Lock className="w-3.5 h-3.5" />
                  HUMAN REVIEW REQUIRED
                </span>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleDecision(hyp.hypothesis_id, 'APPROVE')}
                    className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shadow"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    Approve & Verify
                  </button>

                  <button
                    onClick={() => {
                      setSelectedHypothesis(hyp);
                      setShowRejectModal(true);
                    }}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-rose-900/60 text-slate-300 hover:text-rose-200 rounded-lg text-xs font-medium transition-colors"
                  >
                    Reject
                  </button>

                  <button
                    onClick={() => handleDecision(hyp.hypothesis_id, 'SKIP')}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 rounded-lg text-xs font-medium transition-colors"
                  >
                    Skip
                  </button>

                  <button
                    onClick={() => handleDecision(hyp.hypothesis_id, 'ALREADY_TESTED')}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 rounded-lg text-xs font-medium transition-colors"
                  >
                    Already Tested
                  </button>

                  <button
                    onClick={() => handleDecision(hyp.hypothesis_id, 'REQUEST_REVERIFICATION')}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 rounded-lg text-xs font-medium transition-colors"
                  >
                    Re-Verify
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Confirmation & Execution Modal */}
      {showConfirmModal && selectedHypothesis && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5">
            <div className="flex items-center gap-3 text-cyan-400">
              <Shield className="w-6 h-6" />
              <h3 className="text-lg font-bold text-slate-100">Confirm Controlled Verification</h3>
            </div>

            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2 text-xs font-mono">
              <div><span className="text-slate-500 font-semibold">TARGET:</span> <span className="text-slate-200">{selectedHypothesis.target}</span></div>
              <div><span className="text-slate-500 font-semibold">ENDPOINT:</span> <span className="text-cyan-400">{selectedHypothesis.endpoint}</span></div>
              <div><span className="text-slate-500 font-semibold">HTTP METHOD:</span> <span className="text-slate-200">{selectedHypothesis.method}</span></div>
              <div><span className="text-slate-500 font-semibold">STRATEGY:</span> <span className="text-slate-200">{selectedHypothesis.verification_strategy}</span></div>
              <div><span className="text-slate-500 font-semibold">REQUEST COST:</span> <span className="text-amber-400">{selectedHypothesis.estimated_requests} req(s)</span></div>
              <div><span className="text-slate-500 font-semibold">REMAINING BUDGET:</span> <span className="text-emerald-400">{budgetInfo.remaining_budget} req(s)</span></div>
            </div>

            <p className="text-sm text-slate-300">
              Executing this experiment will dispatch <strong className="text-white">{selectedHypothesis.estimated_requests} safe HTTP request(s)</strong> through the locked RequestEngine pipeline.
            </p>

            <label className="flex items-start gap-3 p-3 bg-slate-950/50 rounded-lg border border-slate-800 cursor-pointer">
              <input
                type="checkbox"
                checked={confirmedRisk}
                onChange={(e) => setConfirmedRisk(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
              />
              <span className="text-xs text-slate-300">
                I authorize this single bounded verification experiment on the explicitly authorized target.
              </span>
            </label>

            {executionResult && (
              <div className={`p-4 rounded-xl border text-xs font-mono ${
                executionResult.status === 'CONFIRMED'
                  ? 'bg-emerald-950/50 border-emerald-800 text-emerald-300'
                  : executionResult.status === 'INCONCLUSIVE'
                  ? 'bg-amber-950/50 border-amber-800 text-amber-300'
                  : 'bg-slate-950 border-slate-800 text-slate-300'
              }`}>
                <div className="font-bold mb-1">VERIFICATION RESULT: {executionResult.status}</div>
                <div>{executionResult.result_details}</div>
                {executionResult.finding_id && (
                  <div className="mt-2 text-cyan-400 font-semibold">Verified Finding ID: {executionResult.finding_id}</div>
                )}
              </div>
            )}

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => {
                  setShowConfirmModal(false);
                  setSelectedHypothesis(null);
                  setExecutionResult(null);
                }}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold"
              >
                Close
              </button>

              {!executionResult && (
                <button
                  disabled={!confirmedRisk || executing}
                  onClick={executeVerification}
                  className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-xs font-bold flex items-center gap-2 shadow-lg"
                >
                  {executing ? (
                    <>
                      <Activity className="w-4 h-4 animate-spin" />
                      Executing...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-current" />
                      Confirm & Execute
                    </>
                  )}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Reject Modal */}
      {showRejectModal && selectedHypothesis && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-slate-100">Reject Vulnerability Hypothesis</h3>
            <p className="text-xs text-slate-400">
              Provide a rationale for why this hypothesis is rejected. This will be logged in the cryptographic audit trail.
            </p>
            <textarea
              value={rejectionReason}
              onChange={(e) => setRejectionReason(e.target.value)}
              placeholder="e.g. Non-sensitive public documentation endpoint"
              className="w-full h-24 bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowRejectModal(false)}
                className="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg text-xs"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  handleDecision(selectedHypothesis.hypothesis_id, 'REJECT', rejectionReason);
                  setShowRejectModal(false);
                  setRejectionReason('');
                }}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold"
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
