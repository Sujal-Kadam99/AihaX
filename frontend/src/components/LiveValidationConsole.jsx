import { useState, useEffect } from 'react';
import { Terminal, ShieldAlert, Play, Square, RefreshCw, AlertTriangle, Hash, Cpu, Lock } from 'lucide-react';
import { executeValidationPlan, stopValidationPlan, reproduceValidationPlan, getValidationPlanObservations } from '../lib/api';

export default function LiveValidationConsole({ campaignId, targetUrl, selectedPlan, onExecutionComplete }) {
  const [executing, setExecuting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [reproducing, setReproducing] = useState(false);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [logs, setLogs] = useState([]);


  const planId = selectedPlan?.id;

  useEffect(() => {
    if (planId) {
      fetchObservations();
    }
  }, [planId]);

  const fetchObservations = async () => {
    if (!planId) return;
    try {
      await getValidationPlanObservations(campaignId, planId);
    } catch (err) {
      console.error('Failed to fetch observations:', err);
    }
  };

  const addLog = (msg, level = 'info') => {
    const timestamp = new Date().toISOString().split('T')[1].slice(0, 8);
    setLogs((prev) => [...prev, { timestamp, msg, level }]);
  };

  const handleDispatch = async () => {
    setShowConfirmModal(false);
    setExecuting(true);
    setLogs([]);
    addLog(`Initiating multi-step validation plan ${planId}...`, 'info');
    addLog(`Target: ${targetUrl}`, 'info');
    addLog(`Enforcing 25-step safety gate: Rate=2 RPS, Concurrency=1, Budget<=10`, 'info');

    try {
      const res = await executeValidationPlan(campaignId, planId, {
        operator_approval_id: selectedPlan?.operator_approval_id || 'APPR-LIVE-01',
        operator_confirmation: 'I CONFIRM AUTHORIZED LIVE DISPATCH',
        execution_mode: 'TEST',
      });

      const data = res?.data?.data || {};

      if (data.step_results) {
        data.step_results.forEach((s) => {
          addLog(`Step ${s.step_number} completed: HTTP ${s.status_code} (hash: ${s.response_hash?.slice(0, 8)}...)`, 'success');
        });
      }

      addLog(`Plan execution finished with verdict: ${data.verdict || 'COMPLETED'}`, data.success ? 'success' : 'warn');
      await fetchObservations();
      if (onExecutionComplete) onExecutionComplete(data);
    } catch (err) {
      addLog(`Execution failed: ${err?.response?.data?.detail || err.message}`, 'error');
    } finally {
      setExecuting(false);
    }
  };

  const handleStop = async () => {
    setStopping(true);
    try {
      await stopValidationPlan(campaignId, planId, { reason: 'Operator requested stop' });
      addLog('Validation plan stopped by operator.', 'warn');
    } catch (err) {
      addLog(`Failed to stop plan: ${err.message}`, 'error');
    } finally {
      setStopping(false);
    }
  };

  const handleReproduce = async () => {
    setReproducing(true);
    addLog('Executing independent reproduction run...', 'info');
    try {
      const res = await reproduceValidationPlan(campaignId, planId, {
        finding_id: 'FIND-001',
        operator_approval_id: selectedPlan?.operator_approval_id || 'APPR-LIVE-01',
        operator_confirmation: 'I CONFIRM REPRODUCTION DISPATCH',
      });
      const data = res?.data?.data || {};
      addLog(`Reproduction result: ${data.result} (score: ${data.reproducibility_score})`, 'success');
    } catch (err) {
      addLog(`Reproduction failed: ${err.message}`, 'error');
    } finally {
      setReproducing(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-100 shadow-xl space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-emerald-500/10 rounded-lg text-emerald-400 border border-emerald-500/20">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white">Live Validation Console</h2>
            <p className="text-xs text-slate-400">
              Deterministic multi-step execution controller for <span className="text-emerald-400 font-mono">{targetUrl || 'Target'}</span>
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setShowConfirmModal(true)}
            disabled={executing || !selectedPlan}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold transition disabled:opacity-50 flex items-center space-x-1.5 shadow-lg shadow-emerald-950"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{executing ? 'Executing Live...' : 'Approve & Dispatch'}</span>
          </button>

          <button
            onClick={handleStop}
            disabled={!executing && stopping}
            className="px-3 py-2 bg-slate-800 hover:bg-red-950/60 text-slate-300 hover:text-red-400 border border-slate-700 hover:border-red-500/40 rounded-lg text-xs font-semibold transition flex items-center space-x-1.5"
          >
            <Square className="w-3.5 h-3.5" />
            <span>Stop</span>
          </button>

          <button
            onClick={handleReproduce}
            disabled={reproducing || !planId}
            className="px-3 py-2 bg-slate-800 hover:bg-indigo-950/60 text-slate-300 hover:text-indigo-400 border border-slate-700 hover:border-indigo-500/40 rounded-lg text-xs font-semibold transition flex items-center space-x-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${reproducing ? 'animate-spin' : ''}`} />
            <span>Reproduce</span>
          </button>
        </div>
      </div>

      {/* Safety Gate Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-800/40 border border-slate-800 p-3 rounded-lg text-xs">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-4 h-4 text-emerald-400" />
          <div>
            <div className="text-slate-400 text-[10px]">Scope Check</div>
            <div className="text-slate-200 font-semibold font-mono">CONCRETE_URL</div>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          <div>
            <div className="text-slate-400 text-[10px]">Rate / Concurrency</div>
            <div className="text-slate-200 font-semibold font-mono">2.0 RPS / 1 Wkr</div>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <Cpu className="w-4 h-4 text-indigo-400" />
          <div>
            <div className="text-slate-400 text-[10px]">Budget Cap</div>
            <div className="text-slate-200 font-semibold font-mono">10 Requests Max</div>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <Hash className="w-4 h-4 text-amber-400" />
          <div>
            <div className="text-slate-400 text-[10px]">Methods Allowed</div>
            <div className="text-slate-200 font-semibold font-mono">GET, HEAD, OPTIONS</div>
          </div>
        </div>
      </div>

      {/* Live Terminal Log */}
      <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs text-slate-300 min-h-[220px] max-h-[300px] overflow-y-auto space-y-1">
        <div className="text-slate-500">{'// AihaX Phase 23 Live Validation Console ready.'}</div>
        {logs.map((l, i) => (
          <div key={i} className="flex items-start space-x-2">
            <span className="text-slate-600">[{l.timestamp}]</span>
            <span
              className={
                l.level === 'error'
                  ? 'text-red-400 font-bold'
                  : l.level === 'warn'
                  ? 'text-amber-400'
                  : l.level === 'success'
                  ? 'text-emerald-400'
                  : 'text-slate-300'
              }
            >
              {l.msg}
            </span>
          </div>
        ))}
      </div>

      {/* Confirmation Modal */}
      {showConfirmModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-amber-500/40 rounded-xl p-6 max-w-md w-full space-y-4 shadow-2xl">
            <div className="flex items-center space-x-3 text-amber-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-lg font-bold">Operator Authorization Warning</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              THIS ACTION WILL SEND A REAL REQUEST TO THE AUTHORIZED TARGET:{' '}
              <span className="text-cyan-400 font-mono font-bold">{targetUrl}</span>.
              <br />
              <br />
              All requests are strictly read-only (GET/HEAD/OPTIONS), bounded to a budget of $\le 10$, and rate-limited to 2 RPS.
            </p>
            <div className="flex justify-end space-x-3 pt-2">
              <button
                onClick={() => setShowConfirmModal(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition"
              >
                Cancel
              </button>
              <button
                onClick={handleDispatch}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold transition shadow-lg"
              >
                APPROVE & DISPATCH LIVE REQUEST
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
