import { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  XCircle,
  SkipForward,
  RotateCcw,
  Sparkles,
  HelpCircle,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Cpu,
  Layers,
  Database,
  Lock,
} from 'lucide-react';
import { Card, CardHeader, CardContent } from './ui/Card';
import Badge from './ui/Badge';
import Button from './ui/Button';
import Modal from './ui/Modal';
import { useToast } from '../hooks/useToast';
import {
  getCampaignHuntingRecommendations,
  logHuntingDecision,
  getCampaignSurfaceInventory,
  getCampaignNegativeEvidence,
} from '../lib/api';

export default function HuntingQueue({ campaignId, targetUrl, requestsUsed = 0, maxBudget = 10 }) {
  const { addToast } = useToast();
  const [recommendations, setRecommendations] = useState([]);
  const [surfaceEntries, setSurfaceEntries] = useState([]);
  const [negativeEvidence, setNegativeEvidence] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState(null);
  const [activeTab, setActiveTab] = useState('recommendations');

  // Confirmation Modal State
  const [selectedRec, setSelectedRec] = useState(null);
  const [modalAction, setModalAction] = useState(null);
  const [actionReason, setActionReason] = useState('');
  const [confirmScopeCheck, setConfirmScopeCheck] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const remainingBudget = Math.max(0, maxBudget - requestsUsed);

  const fetchHuntingData = async () => {
    if (!campaignId) return;
    setLoading(true);
    try {
      const [recRes, surfRes, negRes] = await Promise.all([
        getCampaignHuntingRecommendations(campaignId).catch(() => ({ data: { data: { recommendations: [] } } })),
        getCampaignSurfaceInventory(campaignId).catch(() => ({ data: { data: { surface_entries: [] } } })),
        getCampaignNegativeEvidence(campaignId).catch(() => ({ data: { data: { negative_evidence: [] } } })),
      ]);

      setRecommendations(recRes.data?.data?.recommendations || []);
      setSurfaceEntries(surfRes.data?.data?.surface_entries || []);
      setNegativeEvidence(negRes.data?.data?.negative_evidence || []);
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Hunting Queue Error',
        message: 'Could not load hunting recommendations.',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHuntingData();
  }, [campaignId]);

  const handleOpenActionModal = (rec, action) => {
    setSelectedRec(rec);
    setModalAction(action);
    setActionReason('');
    setConfirmScopeCheck(false);
  };

  const handleCloseModal = () => {
    setSelectedRec(null);
    setModalAction(null);
    setActionReason('');
    setConfirmScopeCheck(false);
  };

  const handleSubmitDecision = async () => {
    if (!selectedRec || !modalAction) return;
    if (modalAction === 'APPROVE' && !confirmScopeCheck) {
      addToast({
        type: 'warning',
        title: 'Confirmation Required',
        message: 'Please confirm that you have reviewed the target authorization boundary.',
      });
      return;
    }

    setSubmitting(true);
    try {
      await logHuntingDecision(campaignId, {
        recommendation_id: selectedRec.id,
        check_id: selectedRec.check_id,
        decision: modalAction,
        reason: actionReason || `Operator selected ${modalAction}`,
        operator_id: 'operator@aihax.local',
      });

      addToast({
        type: 'success',
        title: 'Decision Logged',
        message: `Recommendation marked as ${modalAction}. Recorded in cryptographic audit trail.`,
      });

      handleCloseModal();
      fetchHuntingData();
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Decision Error',
        message: err.response?.data?.detail || 'Failed to record decision.',
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Target & Budget Overview Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-5 h-5 text-cyan-400" />
              <h3 className="text-lg font-bold text-white tracking-wide">Operator Hunting Intelligence</h3>
              <Badge variant="cyan" size="sm">Phase 20</Badge>
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-400">
              <span>Target: <strong className="text-slate-200">{targetUrl || 'WAITING_FOR_TARGET'}</strong></span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                Scope: <strong className="text-emerald-400">Concrete Target Locked</strong>
              </span>
            </div>
          </div>

          {/* Budget Meter */}
          <div className="flex items-center gap-4 bg-slate-950 px-4 py-2.5 rounded-lg border border-slate-800">
            <div>
              <div className="text-xs text-slate-400 font-medium">Production Request Budget</div>
              <div className="text-sm font-bold text-white flex items-center gap-1.5">
                <span className="text-cyan-400">{requestsUsed}</span> / {maxBudget} Requests Used
              </div>
            </div>
            <div className="w-24 bg-slate-800 h-2 rounded-full overflow-hidden">
              <div
                className="bg-cyan-500 h-full transition-all duration-300"
                style={{ width: `${Math.min(100, (requestsUsed / maxBudget) * 100)}%` }}
              />
            </div>
            <Badge variant={remainingBudget > 3 ? 'success' : remainingBudget > 0 ? 'warning' : 'danger'}>
              {remainingBudget} Left
            </Badge>
          </div>
        </div>

        {/* Human Review Disclaimer */}
        <div className="mt-4 flex items-center gap-2.5 bg-amber-950/40 border border-amber-800/60 px-3.5 py-2 rounded-lg text-xs text-amber-200">
          <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
          <span>
            <strong>HUMAN REVIEW REQUIRED:</strong> AihaX ranks and recommends candidate checks based on observed surface and deterministic utility. Operator approval is strictly required before any check execution.
          </span>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('recommendations')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
            activeTab === 'recommendations'
              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Sparkles className="w-3.5 h-3.5" />
          Recommended Checks ({recommendations.length})
        </button>

        <button
          onClick={() => setActiveTab('surface')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
            activeTab === 'surface'
              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          Surface Inventory ({surfaceEntries.length})
        </button>

        <button
          onClick={() => setActiveTab('negative')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
            activeTab === 'negative'
              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          Negative Evidence ({negativeEvidence.length})
        </button>
      </div>

      {/* TAB 1: RECOMMENDATIONS */}
      {activeTab === 'recommendations' && (
        <div className="space-y-4">
          {loading ? (
            <div className="text-center py-12 text-slate-500 text-sm animate-pulse">
              Computing deterministic check utility and ranking attack surface...
            </div>
          ) : recommendations.length === 0 ? (
            <Card className="text-center py-10 bg-slate-900/60 border-slate-800">
              <p className="text-slate-400 text-sm">No pending recommendations for this target.</p>
            </Card>
          ) : (
            recommendations.map((rec) => {
              const isExpanded = expandedId === rec.id;
              return (
                <Card
                  key={rec.id}
                  className="bg-slate-900/90 border-slate-800 hover:border-slate-700 transition-all shadow-md overflow-hidden"
                >
                  <div className="p-4 sm:p-5">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="flex items-start gap-3">
                        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400 font-bold text-xs">
                          #{rec.rank}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="text-sm font-bold text-white">{rec.check_name}</h4>
                            <Badge variant="cyan" size="sm">{rec.category}</Badge>
                            <Badge variant={rec.risk_level === 'SAFE_ACTIVE' ? 'success' : 'default'} size="sm">
                              {rec.risk_level}
                            </Badge>
                          </div>
                          <p className="text-xs text-slate-400 mt-1">{rec.reason}</p>
                        </div>
                      </div>

                      {/* Utility & Request Estimates */}
                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <div className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Utility Score</div>
                          <div className="text-sm font-extrabold text-cyan-400 font-mono">
                            {(rec.utility_score * 100).toFixed(0)}%
                          </div>
                        </div>
                        <div className="text-right border-l border-slate-800 pl-3">
                          <div className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Estimated Reqs</div>
                          <div className="text-sm font-bold text-slate-300 font-mono">
                            {rec.estimated_requests} req
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Expandable Technical Details */}
                    {isExpanded && (
                      <div className="mt-4 pt-4 border-t border-slate-800/80 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/60">
                          <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px] block mb-1">
                            Expected Evidence
                          </span>
                          <p className="text-slate-300 leading-relaxed">{rec.expected_evidence}</p>
                        </div>
                        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/60">
                          <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px] block mb-1">
                            Historical & Memory Provenance
                          </span>
                          <p className="text-slate-300 leading-relaxed">{rec.supporting_historical_evidence}</p>
                        </div>
                      </div>
                    )}

                    {/* Operator Action Buttons */}
                    <div className="mt-4 pt-3 border-t border-slate-800/60 flex flex-wrap items-center justify-between gap-2">
                      <button
                        onClick={() => setExpandedId(isExpanded ? null : rec.id)}
                        className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 font-medium transition-colors"
                      >
                        {isExpanded ? (
                          <>
                            <ChevronUp className="w-3.5 h-3.5" /> Hide Details
                          </>
                        ) : (
                          <>
                            <ChevronDown className="w-3.5 h-3.5" /> Review Evidence Contract
                          </>
                        )}
                      </button>

                      <div className="flex items-center gap-1.5">
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={() => handleOpenActionModal(rec, 'SKIP')}
                          className="text-slate-400 hover:text-slate-200"
                        >
                          <SkipForward className="w-3 h-3 mr-1" /> Skip
                        </Button>
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={() => handleOpenActionModal(rec, 'REJECT')}
                          className="text-rose-400 hover:text-rose-300"
                        >
                          <XCircle className="w-3 h-3 mr-1" /> Reject
                        </Button>
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={() => handleOpenActionModal(rec, 'ALREADY_TESTED')}
                          className="text-amber-400 hover:text-amber-300"
                        >
                          <CheckCircle className="w-3 h-3 mr-1" /> Tested
                        </Button>
                        <Button
                          variant="primary"
                          size="xs"
                          onClick={() => handleOpenActionModal(rec, 'APPROVE')}
                          className="bg-cyan-600 hover:bg-cyan-500 font-semibold"
                        >
                          Approve & Review Plan
                        </Button>
                      </div>
                    </div>
                  </div>
                </Card>
              );
            })
          )}
        </div>
      )}

      {/* TAB 2: SURFACE INVENTORY */}
      {activeTab === 'surface' && (
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-2">
            <h4 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Observed Authorized Surface Inventory
            </h4>
            <p className="text-xs text-slate-400">
              Deterministic index populated exclusively from authorized assessment responses. Zero active discovery performed.
            </p>
          </CardHeader>
          <CardContent>
            {surfaceEntries.length === 0 ? (
              <div className="text-center py-8 text-slate-500 text-xs">No surface entries observed yet.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                      <th className="py-2.5 px-3">Method</th>
                      <th className="py-2.5 px-3">Normalized Path</th>
                      <th className="py-2.5 px-3">Parameters</th>
                      <th className="py-2.5 px-3">Auth State</th>
                      <th className="py-2.5 px-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300 font-mono">
                    {surfaceEntries.map((s) => (
                      <tr key={s.id} className="hover:bg-slate-800/40">
                        <td className="py-2 px-3 font-bold text-cyan-400">{s.http_method}</td>
                        <td className="py-2 px-3">{s.normalized_path}</td>
                        <td className="py-2 px-3 text-slate-400">{s.parameters?.join(', ') || 'none'}</td>
                        <td className="py-2 px-3">
                          <Badge variant={s.auth_state === 'AUTHENTICATED' ? 'success' : 'default'} size="sm">
                            {s.auth_state}
                          </Badge>
                        </td>
                        <td className="py-2 px-3">{s.status_code || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* TAB 3: NEGATIVE EVIDENCE */}
      {activeTab === 'negative' && (
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-2">
            <h4 className="text-sm font-bold text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-emerald-400" />
              Recorded Negative Evidence Records
            </h4>
            <p className="text-xs text-slate-400">
              Verified non-vulnerable conditions observed on authorized targets, preventing redundant probe repetition.
            </p>
          </CardHeader>
          <CardContent>
            {negativeEvidence.length === 0 ? (
              <div className="text-center py-8 text-slate-500 text-xs">No negative evidence recorded yet.</div>
            ) : (
              <div className="space-y-3">
                {negativeEvidence.map((n) => (
                  <div key={n.id} className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold text-white font-mono">{n.check_id}</span>
                      <Badge variant="success" size="sm">{n.verdict}</Badge>
                    </div>
                    <p className="text-slate-400 mt-1 font-mono text-[11px]">{n.endpoint}</p>
                    <div className="mt-2 text-[10px] text-slate-500 flex gap-4 font-mono">
                      <span>Req Hash: {n.request_hash.slice(0, 16)}...</span>
                      <span>Resp Hash: {n.response_hash.slice(0, 16)}...</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Human Operator Action Confirmation Modal */}
      {modalAction && selectedRec && (
        <Modal
          isOpen={true}
          onClose={handleCloseModal}
          title={`Confirm Action: ${modalAction}`}
        >
          <div className="space-y-4 text-xs text-slate-300">
            <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-1.5">
              <div className="flex justify-between">
                <span className="text-slate-400">Check Name:</span>
                <strong className="text-white">{selectedRec.check_name}</strong>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Target URL:</span>
                <strong className="text-cyan-400 font-mono">{selectedRec.target}</strong>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Estimated Requests:</span>
                <strong className="text-slate-200">{selectedRec.estimated_requests} reqs</strong>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Current Budget Remaining:</span>
                <strong className="text-emerald-400">{remainingBudget} / {maxBudget}</strong>
              </div>
            </div>

            {modalAction === 'APPROVE' && (
              <label className="flex items-start gap-2.5 p-3 bg-cyan-950/30 border border-cyan-800/40 rounded-lg cursor-pointer">
                <input
                  type="checkbox"
                  checked={confirmScopeCheck}
                  onChange={(e) => setConfirmScopeCheck(e.target.checked)}
                  className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
                />
                <span className="text-slate-200 leading-snug">
                  I confirm this concrete target is within explicit authorization boundaries and approve logging this safe check decision.
                </span>
              </label>
            )}

            <div>
              <label className="block text-slate-400 font-semibold mb-1">
                Operator Review Notes (Optional):
              </label>
              <textarea
                value={actionReason}
                onChange={(e) => setActionReason(e.target.value)}
                placeholder="Add audit notes regarding this decision..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                rows={3}
              />
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={handleCloseModal}>
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={handleSubmitDecision}
                disabled={submitting || (modalAction === 'APPROVE' && !confirmScopeCheck)}
                className="bg-cyan-600 hover:bg-cyan-500"
              >
                {submitting ? 'Recording Audit...' : `Confirm ${modalAction}`}
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
