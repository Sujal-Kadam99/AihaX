import { useState, useEffect } from 'react';
import { ListOrdered, Shield, CheckCircle, Lock } from 'lucide-react';
import { getValidationPlans, approveValidationPlan } from '../lib/api';


export default function ValidationPlanViewer({ campaignId, targetUrl, onSelectPlan }) {
  const [plans, setPlans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedPlanId, setSelectedPlanId] = useState(null);
  const [approvingId, setApprovingId] = useState(null);

  useEffect(() => {
    fetchPlans();
  }, [campaignId]);

  const fetchPlans = async () => {
    setLoading(true);
    try {
      const res = await getValidationPlans(campaignId);
      if (res?.data?.data?.plans) {
        setPlans(res.data.data.plans);
        if (res.data.data.plans.length > 0 && !selectedPlanId) {
          setSelectedPlanId(res.data.data.plans[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch validation plans:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (planId) => {
    setApprovingId(planId);
    try {
      await approveValidationPlan(campaignId, planId, {
        operator_confirmation: 'I CONFIRM AUTHORIZATION FOR PLAN DISPATCH',
        reason: 'Operator approved plan execution',
      });
      await fetchPlans();
    } catch (err) {
      console.error('Failed to approve plan:', err);
    } finally {
      setApprovingId(null);
    }
  };

  const selectedPlan = plans.find((p) => p.id === selectedPlanId);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-100 shadow-xl space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-indigo-500/10 rounded-lg text-indigo-400 border border-indigo-500/20">
            <ListOrdered className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white">Multi-Step Validation Plans</h2>
            <p className="text-xs text-slate-400">
              Bounded 2–5 step safe validation plans for <span className="text-indigo-400 font-mono">{targetUrl || 'Target'}</span>
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <Lock className="w-3.5 h-3.5 mr-1" />
            Max 10 Requests Locked
          </span>
        </div>
      </div>

      {loading ? (
        <div className="py-12 text-center text-slate-500">Loading validation plans...</div>
      ) : plans.length === 0 ? (
        <div className="py-12 text-center text-slate-500">No validation plans generated for this campaign.</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Plan Selector List */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Available Plans ({plans.length})</h3>
            <div className="space-y-2">
              {plans.map((p) => (
                <div
                  key={p.id}
                  onClick={() => {
                    setSelectedPlanId(p.id);
                    if (onSelectPlan) onSelectPlan(p);
                  }}
                  className={`p-4 rounded-lg border cursor-pointer transition ${
                    selectedPlanId === p.id
                      ? 'bg-indigo-950/40 border-indigo-500/60 shadow-lg'
                      : 'bg-slate-800/40 border-slate-800 hover:bg-slate-800/70'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs text-indigo-400 font-bold">{p.id}</span>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                        p.status === 'APPROVED' || p.status === 'COMPLETED'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}
                    >
                      {p.status}
                    </span>
                  </div>
                  <div className="text-xs font-medium text-slate-200 mt-2 truncate">
                    Hypothesis: {p.hypothesis_id}
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                    <span>{p.steps?.length || 0} Steps</span>
                    <span>Budget Cost: {p.estimated_requests} reqs</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Plan Detail Viewer */}
          {selectedPlan && (
            <div className="lg:col-span-2 bg-slate-800/30 border border-slate-800 rounded-xl p-5 space-y-5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-base font-bold text-white">Plan Specification: {selectedPlan.id}</h3>
                  <div className="text-xs text-slate-400 mt-0.5">Version: {selectedPlan.plan_version}</div>
                </div>
                {selectedPlan.status !== 'APPROVED' && selectedPlan.status !== 'COMPLETED' && (
                  <button
                    onClick={() => handleApprove(selectedPlan.id)}
                    disabled={approvingId === selectedPlan.id}
                    className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition disabled:opacity-50 flex items-center space-x-1.5"
                  >
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>{approvingId === selectedPlan.id ? 'Approving...' : 'Approve Plan'}</span>
                  </button>
                )}
              </div>

              {/* Steps Timeline */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Step Sequence</h4>
                <div className="space-y-2">
                  {selectedPlan.steps?.map((step) => (
                    <div key={step.id} className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-3.5 flex items-start space-x-3">
                      <div className="w-6 h-6 rounded-full bg-indigo-500/20 text-indigo-400 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">
                        {step.step_number}
                      </div>
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs text-emerald-400 font-bold mr-2">
                            {step.method} <span className="text-slate-200">{step.endpoint}</span>
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono">Cost: {step.request_cost} req</span>
                        </div>
                        <p className="text-xs text-slate-300">{step.expected_observation}</p>
                        <div className="text-[11px] text-slate-500 font-mono mt-1">
                          Success Cond: {step.success_condition}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Safety Constraints Box */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3 text-xs text-slate-400 space-y-1">
                <div className="text-slate-300 font-semibold flex items-center space-x-1.5">
                  <Shield className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Enforced Safety Policy</span>
                </div>
                <div className="grid grid-cols-2 gap-2 pt-1 font-mono text-[11px]">
                  <div>Rate Limit: 2.0 RPS max</div>
                  <div>Concurrency: 1 worker locked</div>
                  <div>Allowed Methods: GET, HEAD, OPTIONS</div>
                  <div>State Mutations: Strictly Forbidden</div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
