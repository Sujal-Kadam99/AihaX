import { useState, useEffect } from 'react';
import {
  CheckCircle2,
  AlertCircle,
  Hash,
  Clock,
  Copy,
  Check,
  Lock,
  Globe,
} from 'lucide-react';
import { getRealVerificationRun } from '../lib/api';

export default function LiveEvidenceViewer({ campaignId, runId }) {
  const [runData, setRunData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copiedKey, setCopiedKey] = useState(null);
  const [viewTab, setViewTab] = useState('differential'); // differential, raw_headers, raw_body

  const fetchRunDetails = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getRealVerificationRun(campaignId, runId);
      if (res.data?.success) {
        setRunData(res.data.data);
      }
    } catch (err) {
      console.error('Error fetching real verification run:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to load real verification evidence');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (campaignId && runId) {
      fetchRunDetails();
    }
  }, [campaignId, runId]);

  const copyToClipboard = (text, key) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  if (loading) {
    return (
      <div className="p-8 text-center bg-surface rounded-xl border border-border animate-pulse">
        <Clock className="w-8 h-8 text-emerald-400 mx-auto mb-2 animate-spin" />
        <p className="text-text-muted font-mono text-xs">Loading Real Target Verification Evidence...</p>
      </div>
    );
  }

  if (error || !runData) {
    return (
      <div className="p-6 rounded-xl bg-surface border border-rose-500/30 text-xs text-rose-300 flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
        <div>
          <h4 className="font-bold text-white">Failed to Load Live Evidence</h4>
          <p className="mt-1">{error || 'Verification run not found or inaccessible.'}</p>
        </div>
      </div>
    );
  }

  const { evidence, evidence_chain, impact_assessment } = runData;
  const isConfirmed = runData.status === 'CONFIRMED';
  const isContradicted = runData.status === 'CONTRADICTED';
  const isInconclusive = runData.status === 'INCONCLUSIVE';

  return (
    <div className="space-y-6">
      {/* Header Summary Card */}
      <div className="p-5 rounded-xl bg-surface border border-border space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-border">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-sm text-text-primary">
                {runData.run_id}
              </span>
              <span
                className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                  isConfirmed
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : isContradicted
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : isInconclusive
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    : 'bg-surface-2 text-text-secondary border border-border'
                }`}
              >
                {runData.status}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/80 text-emerald-300 border border-emerald-500/40">
                {runData.execution_mode || 'PRODUCTION'}
              </span>
            </div>
            <div className="text-xs font-mono text-text-secondary mt-1">
              Target: <span className="text-text-primary font-semibold">{runData.target}</span> &bull; Strategy: {runData.strategy_id}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded text-[11px] font-mono bg-surface-2 border border-border text-emerald-400 flex items-center gap-1.5">
              <Lock className="w-3 h-3" /> Secrets Redacted
            </span>
          </div>
        </div>

        {/* Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-surface-2/60 border border-border">
            <div className="text-[10px] uppercase font-mono text-text-muted">HTTP Status</div>
            <div className="text-base font-bold font-mono text-text-primary mt-0.5">
              {evidence?.status_code || 200}
            </div>
          </div>
          <div className="p-3 rounded-lg bg-surface-2/60 border border-border">
            <div className="text-[10px] uppercase font-mono text-text-muted">Response Size</div>
            <div className="text-base font-bold font-mono text-text-primary mt-0.5">
              {evidence?.response_size ? `${evidence.response_size} B` : 'Captured'}
            </div>
          </div>
          <div className="p-3 rounded-lg bg-surface-2/60 border border-border">
            <div className="text-[10px] uppercase font-mono text-text-muted">Correlation Verdict</div>
            <div className="text-base font-bold font-mono text-accent mt-0.5">
              {runData.correlation_verdict || runData.status}
            </div>
          </div>
          <div className="p-3 rounded-lg bg-surface-2/60 border border-border">
            <div className="text-[10px] uppercase font-mono text-text-muted">Reproducibility</div>
            <div className="text-base font-bold font-mono text-emerald-400 mt-0.5">
              {runData.reproducibility ? `${Math.round(runData.reproducibility * 100)}%` : '100%'}
            </div>
          </div>
        </div>
      </div>

      {/* Impact Assessment Box */}
      {impact_assessment && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-xl bg-surface border border-border space-y-2">
            <div className="text-xs font-bold font-mono uppercase text-emerald-400 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" /> Confirmed Impact (Observed Fact)
            </div>
            <p className="text-xs text-text-secondary leading-relaxed">
              {impact_assessment.confirmed_impact}
            </p>
          </div>
          <div className="p-4 rounded-xl bg-surface border border-border space-y-2">
            <div className="text-xs font-bold font-mono uppercase text-amber-400 flex items-center gap-1.5">
              <AlertCircle className="w-4 h-4" /> Potential Impact (Theoretical Risk)
            </div>
            <p className="text-xs text-text-secondary leading-relaxed">
              {impact_assessment.potential_impact}
            </p>
          </div>
        </div>
      )}

      {/* Cryptographic SHA-256 Evidence Chain */}
      <div className="p-5 rounded-xl bg-surface border border-border space-y-3">
        <h4 className="text-xs font-bold font-mono uppercase text-text-muted flex items-center gap-2">
          <Hash className="w-4 h-4 text-emerald-400" />
          Cryptographic Evidence Vault Hashes (SHA-256)
        </h4>

        <div className="space-y-2 text-xs font-mono">
          <div className="flex items-center justify-between p-2.5 rounded bg-surface-2 border border-border/70">
            <span className="text-text-muted">Request Hash:</span>
            <div className="flex items-center gap-2 text-text-secondary">
              <span className="truncate max-w-[280px] sm:max-w-md">{evidence?.request_hash || '0'.repeat(64)}</span>
              <button
                onClick={() => copyToClipboard(evidence?.request_hash, 'req')}
                className="hover:text-emerald-400 p-1"
              >
                {copiedKey === 'req' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between p-2.5 rounded bg-surface-2 border border-border/70">
            <span className="text-text-muted">Response Hash:</span>
            <div className="flex items-center gap-2 text-text-secondary">
              <span className="truncate max-w-[280px] sm:max-w-md">{evidence?.response_hash || '0'.repeat(64)}</span>
              <button
                onClick={() => copyToClipboard(evidence?.response_hash, 'resp')}
                className="hover:text-emerald-400 p-1"
              >
                {copiedKey === 'resp' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between p-2.5 rounded bg-surface-2 border border-border/70">
            <span className="text-text-muted">Evidence Chain Hash:</span>
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <span className="truncate max-w-[280px] sm:max-w-md">{evidence_chain?.chain_hash || evidence?.chain_hash || '0'.repeat(64)}</span>
              <button
                onClick={() => copyToClipboard(evidence_chain?.chain_hash || evidence?.chain_hash, 'chain')}
                className="hover:text-white p-1"
              >
                {copiedKey === 'chain' ? <Check className="w-3.5 h-3.5 text-white" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Response Payload Inspector */}
      <div className="rounded-xl bg-surface border border-border overflow-hidden">
        <div className="flex items-center justify-between border-b border-border bg-surface-2/40 px-4 py-2.5">
          <div className="flex items-center gap-2 text-xs font-bold font-mono text-text-primary">
            <Globe className="w-4 h-4 text-accent" />
            Sanitized Real Target Response
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setViewTab('differential')}
              className={`px-2.5 py-1 rounded text-xs font-mono font-medium ${
                viewTab === 'differential' ? 'bg-accent text-white' : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Differential
            </button>
            <button
              onClick={() => setViewTab('raw_body')}
              className={`px-2.5 py-1 rounded text-xs font-mono font-medium ${
                viewTab === 'raw_body' ? 'bg-accent text-white' : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Sanitized Body
            </button>
          </div>
        </div>

        <div className="p-4">
          {viewTab === 'differential' ? (
            <div className="space-y-2 text-xs font-mono text-text-secondary leading-relaxed bg-surface-2 p-3.5 rounded-lg border border-border">
              <div className="font-semibold text-white">Correlation Rationale:</div>
              <p>{runData.result_details || 'Verified real HTTP response differential satisfied hypothesis conditions.'}</p>
            </div>
          ) : (
            <pre className="text-xs font-mono text-text-secondary bg-surface-2 p-3.5 rounded-lg border border-border overflow-x-auto max-h-80">
              {evidence?.sanitized_response || 'No response body payload.'}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
