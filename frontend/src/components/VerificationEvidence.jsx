import { useState, useEffect } from 'react';
import {
  FileCheck,
  CheckCircle2,
  AlertCircle,
  Hash,
  Clock,
  ArrowRightLeft,
  Copy,
  Check,
  Lock,
} from 'lucide-react';
import { api } from '../lib/api';

export default function VerificationEvidence({ campaignId, verificationId }) {
  const [verificationData, setVerificationData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copiedKey, setCopiedKey] = useState(null);
  const [viewMode, setViewMode] = useState('differential'); // differential, raw_req, raw_resp

  const fetchVerificationDetails = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get(`/api/campaigns/${campaignId}/verifications/${verificationId}`);
      if (res.data?.success) {
        setVerificationData(res.data.data);
      }
    } catch (err) {
      console.error('Error fetching verification run:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to load verification evidence');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (campaignId && verificationId) {
      fetchVerificationDetails();
    }
  }, [campaignId, verificationId]);

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  if (loading) {
    return (
      <div className="p-8 text-center bg-slate-900/40 rounded-xl border border-slate-800 animate-pulse">
        <Clock className="w-8 h-8 text-cyan-400 mx-auto mb-2 animate-spin" />
        <p className="text-slate-400 font-mono text-sm">Loading Cryptographic Verification Evidence...</p>
      </div>
    );
  }

  if (error || !verificationData) {
    return (
      <div className="p-6 bg-slate-900/50 rounded-xl border border-slate-800 text-center">
        <AlertCircle className="w-8 h-8 text-rose-400 mx-auto mb-2" />
        <p className="text-rose-300 font-mono text-sm">{error || 'Verification record not found'}</p>
      </div>
    );
  }

  const { run_id, strategy_id, status, result_details, finding_id, evidence } = verificationData;

  return (
    <div className="space-y-6">
      {/* Header Summary */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg backdrop-blur space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <FileCheck className="w-5 h-5 text-cyan-400" />
              <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400">Verification Evidence Record</span>
            </div>
            <p className="text-base font-mono font-bold text-slate-100">{run_id}</p>
          </div>

          <div className="flex items-center gap-3">
            <span
              className={`px-3 py-1 text-xs font-bold rounded-full uppercase tracking-wider font-mono ${
                status === 'CONFIRMED'
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : status === 'INCONCLUSIVE'
                  ? 'bg-amber-950 text-amber-400 border border-amber-800'
                  : 'bg-slate-800 text-slate-300 border border-slate-700'
              }`}
            >
              {status}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-3 border-t border-slate-800 text-xs font-mono">
          <div>
            <span className="text-slate-500 font-semibold block">STRATEGY CONTRACT</span>
            <span className="text-slate-200">{strategy_id}</span>
          </div>
          <div>
            <span className="text-slate-500 font-semibold block">VERIFIER VERSION</span>
            <span className="text-slate-200">{evidence?.verifier_version || '1.0.0-phase21'}</span>
          </div>
          <div>
            <span className="text-slate-500 font-semibold block">LINKED FINDING</span>
            <span className="text-cyan-400">{finding_id || 'None (Safe Condition)'}</span>
          </div>
        </div>
      </div>

      {/* Cryptographic Integrity Card */}
      {evidence && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4 shadow-md">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Hash className="w-4 h-4 text-cyan-400" />
              Cryptographic Integrity Hashes (SHA-256)
            </h4>
            <span className="text-xs text-emerald-400 flex items-center gap-1 font-mono">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Immutable & Tamper-Evident
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80 space-y-1">
              <div className="text-slate-500 flex items-center justify-between">
                <span>REQUEST HASH:</span>
                <button
                  onClick={() => copyToClipboard(evidence.request_hash, 'req_hash')}
                  className="text-slate-400 hover:text-cyan-400"
                >
                  {copiedKey === 'req_hash' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="text-slate-200 truncate">{evidence.request_hash}</div>
            </div>

            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80 space-y-1">
              <div className="text-slate-500 flex items-center justify-between">
                <span>RESPONSE HASH:</span>
                <button
                  onClick={() => copyToClipboard(evidence.response_hash, 'resp_hash')}
                  className="text-slate-400 hover:text-cyan-400"
                >
                  {copiedKey === 'resp_hash' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="text-slate-200 truncate">{evidence.response_hash}</div>
            </div>
          </div>
        </div>
      )}

      {/* Differential Evidence & Raw Payloads */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-md">
        <div className="flex border-b border-slate-800 bg-slate-950/40 text-xs font-mono">
          <button
            onClick={() => setViewMode('differential')}
            className={`px-4 py-3 border-b-2 font-semibold transition-colors ${
              viewMode === 'differential'
                ? 'border-cyan-500 text-cyan-400 bg-slate-900/60'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Differential Verdict & Analysis
          </button>
          <button
            onClick={() => setViewMode('raw_req')}
            className={`px-4 py-3 border-b-2 font-semibold transition-colors ${
              viewMode === 'raw_req'
                ? 'border-cyan-500 text-cyan-400 bg-slate-900/60'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Sanitized Request Proof
          </button>
          <button
            onClick={() => setViewMode('raw_resp')}
            className={`px-4 py-3 border-b-2 font-semibold transition-colors ${
              viewMode === 'raw_resp'
                ? 'border-cyan-500 text-cyan-400 bg-slate-900/60'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Sanitized Response Proof
          </button>
        </div>

        <div className="p-5">
          {viewMode === 'differential' && (
            <div className="space-y-4">
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="text-xs font-bold text-slate-300 font-mono flex items-center gap-2">
                  <ArrowRightLeft className="w-4 h-4 text-cyan-400" />
                  ANALYSIS RATIONALE:
                </div>
                <p className="text-sm text-slate-300 font-mono">{result_details}</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-slate-950/60 rounded-xl border border-slate-800 space-y-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 font-mono block">
                    Confirmed Impact (Observed Fact)
                  </span>
                  <p className="text-xs text-slate-300">
                    Directly demonstrated by the captured HTTP response status and header evidence. Zero assumptions or unobserved states.
                  </p>
                </div>

                <div className="p-4 bg-slate-950/60 rounded-xl border border-slate-800 space-y-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-amber-400 font-mono block">
                    Potential Impact [INFERENCE]
                  </span>
                  <p className="text-xs text-slate-300">
                    [INFERENCE] Theoretical security risk if component is exposed without secondary defense-in-depth controls.
                  </p>
                </div>
              </div>
            </div>
          )}

          {viewMode === 'raw_req' && (
            <div className="space-y-2 font-mono">
              <div className="flex items-center justify-between text-xs text-slate-400 pb-1">
                <span className="flex items-center gap-1.5"><Lock className="w-3.5 h-3.5 text-amber-400" /> Secrets & Tokens Redacted</span>
                <button
                  onClick={() => copyToClipboard(evidence?.sanitized_request || '', 'raw_req')}
                  className="text-cyan-400 hover:underline flex items-center gap-1 text-xs"
                >
                  <Copy className="w-3 h-3" /> Copy Request
                </button>
              </div>
              <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs text-slate-200 overflow-x-auto whitespace-pre-wrap">
                {evidence?.sanitized_request || 'No request payload recorded.'}
              </pre>
            </div>
          )}

          {viewMode === 'raw_resp' && (
            <div className="space-y-2 font-mono">
              <div className="flex items-center justify-between text-xs text-slate-400 pb-1">
                <span className="flex items-center gap-1.5"><Lock className="w-3.5 h-3.5 text-amber-400" /> Secrets Redacted</span>
                <button
                  onClick={() => copyToClipboard(evidence?.sanitized_response || '', 'raw_resp')}
                  className="text-cyan-400 hover:underline flex items-center gap-1 text-xs"
                >
                  <Copy className="w-3 h-3" /> Copy Response
                </button>
              </div>
              <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs text-slate-200 overflow-x-auto whitespace-pre-wrap">
                {evidence?.sanitized_response || 'No response payload recorded.'}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
