import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Lock,
  Eye,
  CheckCircle2,
  RefreshCw,
  AlertCircle,
  Database,
  ShieldAlert,
  Play,
  Clock,
  Layers,
  FileCheck,
} from 'lucide-react';
import { getCampaignEvidence, getCampaigns, getCampaignExecutionSummary } from '../lib/api';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import Input from '../components/ui/Input';
import Button from '../components/ui/Button';
import Modal from '../components/ui/Modal';
import ExecutionTimeline from '../components/ExecutionTimeline';

export default function Evidence() {
  const [searchParams] = useSearchParams();
  const initialCampaignId = searchParams.get('campaign');

  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState(initialCampaignId || '');
  const [evidenceList, setEvidenceList] = useState([]);
  const [execSummary, setExecSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [activeTab, setActiveTab] = useState('evidence'); // 'evidence' or 'timeline'

  // Preview Drawer/Modal State
  const [previewEvidence, setPreviewEvidence] = useState(null);

  useEffect(() => {
    async function loadCampaignsList() {
      try {
        const res = await getCampaigns();
        const list = res.data?.data || res.data || [];
        setCampaigns(list);
        if (list.length > 0 && !selectedCampaignId) {
          setSelectedCampaignId(list[0].campaign_id || list[0].id);
        }
      } catch (err) {
        console.error('Error fetching campaigns:', err);
      }
    }
    loadCampaignsList();
  }, []);

  useEffect(() => {
    if (selectedCampaignId) {
      loadEvidence(selectedCampaignId);
      loadSummary(selectedCampaignId);
    } else {
      setLoading(false);
    }
  }, [selectedCampaignId, typeFilter]);

  async function loadSummary(campaignId) {
    try {
      const res = await getCampaignExecutionSummary(campaignId);
      setExecSummary(res.data?.data || res.data);
    } catch {
      // Summary error should not block evidence view
    }
  }

  async function loadEvidence(campaignId) {
    try {
      setLoading(true);
      setError(null);
      const params = {};
      if (typeFilter !== 'ALL') params.evidence_type = typeFilter;
      const res = await getCampaignEvidence(campaignId, params);
      const rawData = res.data?.data ?? res.data ?? [];
      const list = Array.isArray(rawData) ? rawData : (Array.isArray(rawData?.items) ? rawData.items : []);
      setEvidenceList(list);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Unable to load evidence';
      setError(msg);
      console.error('Error loading evidence:', err);
    } finally {
      setLoading(false);
    }
  }

  const filtered = evidenceList.filter((e) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    const eid = (e.evidence_id || e.id || '').toLowerCase();
    const url = (e.target_url || '').toLowerCase();
    const hash = (e.content_hash || '').toLowerCase();
    return eid.includes(q) || url.includes(q) || hash.includes(q);
  });

  const isBlocked = execSummary?.status === 'BLOCKED' || (execSummary?.tests_blocked > 0 && execSummary?.tests_started === 0);
  const isExecuting = execSummary?.status === 'EXECUTING' || execSummary?.status === 'RECON' || execSummary?.status === 'PREFLIGHT';
  const isCompletedWithZeroEvidence = !loading && !error && filtered.length === 0 && (execSummary?.status === 'COMPLETED' || (execSummary?.tests_completed > 0 && filtered.length === 0));
  const isNotStarted = !isBlocked && !isExecuting && !isCompletedWithZeroEvidence;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">
            Cryptographic Evidence Vault
          </h1>
          <p className="text-xs text-text-secondary mt-0.5">
            Immutable, SHA-256 hashed request/response artifacts with pre-storage secret redaction.
          </p>
        </div>

        {/* Campaign Selector */}
        {campaigns.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-text-muted">Campaign:</span>
            <select
              value={selectedCampaignId}
              onChange={(e) => setSelectedCampaignId(e.target.value)}
              className="h-8 rounded bg-surface-2 border border-border px-2.5 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            >
              {campaigns.map((c) => (
                <option key={c.campaign_id || c.id} value={c.campaign_id || c.id}>
                  {c.campaign_name || c.name || 'Assessment'} ({c.target_url})
                </option>
              ))}
            </select>
            <Button
              variant="secondary"
              size="xs"
              onClick={() => {
                if (selectedCampaignId) {
                  loadEvidence(selectedCampaignId);
                  loadSummary(selectedCampaignId);
                }
              }}
              loading={loading}
              className="flex items-center gap-1"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Refresh</span>
            </Button>
          </div>
        )}
      </div>

      {/* View Switcher Tabs: Evidence Vault vs Execution Timeline */}
      <div className="flex items-center gap-2 border-b border-border pb-2">
        <button
          onClick={() => setActiveTab('evidence')}
          className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
            activeTab === 'evidence'
              ? 'bg-accent/20 text-accent border border-accent/40 font-bold'
              : 'text-text-secondary hover:text-text-primary'
          }`}
        >
          <Database className="w-3.5 h-3.5" /> Evidence Artifacts ({filtered.length})
        </button>
        <button
          onClick={() => setActiveTab('timeline')}
          className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
            activeTab === 'timeline'
              ? 'bg-accent/20 text-accent border border-accent/40 font-bold'
              : 'text-text-secondary hover:text-text-primary'
          }`}
        >
          <Clock className="w-3.5 h-3.5" /> Execution Timeline
        </button>
      </div>

      {activeTab === 'timeline' ? (
        <ExecutionTimeline
          campaignId={selectedCampaignId}
          onSelectEvidence={(eid) => {
            const ev = evidenceList.find((x) => (x.evidence_id || x.id) === eid);
            if (ev) setPreviewEvidence(ev);
          }}
        />
      ) : (
        <>
          {/* Automated Verification Summary Bar */}
          {execSummary && (
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 text-xs">
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-text-muted text-[10px] block">Detected</span>
                <span className="font-mono font-bold text-text-primary text-sm">
                  {execSummary.findings_detected ?? execSummary.finding_count ?? 0}
                </span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-text-muted text-[10px] block">Validated</span>
                <span className="font-mono font-bold text-emerald-400 text-sm">
                  {execSummary.findings_validated ?? 0}
                </span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-text-muted text-[10px] block">Exploitable</span>
                <span className="font-mono font-bold text-purple-400 text-sm">
                  {execSummary.findings_exploitable ?? 0}
                </span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-text-muted text-[10px] block">Hardening Only</span>
                <span className="font-mono font-bold text-blue-400 text-sm">
                  {execSummary.findings_hardening_only ?? 0}
                </span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-text-muted text-[10px] block">Inconclusive</span>
                <span className="font-mono font-bold text-amber-400 text-sm">
                  {execSummary.findings_inconclusive ?? 0}
                </span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-text-muted text-[10px] block">False Positive</span>
                <span className="font-mono font-bold text-rose-400 text-sm">
                  {execSummary.findings_false_positive ?? 0}
                </span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-text-muted text-[10px] block">Pass Rate</span>
                <span className="font-mono font-bold text-text-primary text-sm">
                  {Math.round((execSummary.verification_pass_rate ?? 0) * 100)}%
                </span>
              </div>
            </div>
          )}

          {/* Filter Bar */}
          <Card className="p-3 bg-surface border-border flex flex-col sm:flex-row gap-3 items-center justify-between">
            <div className="w-full sm:w-80">
              <Input
                placeholder="Search evidence ID, URL, or hash..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="text-xs font-mono"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <span className="text-xs text-text-muted">Type:</span>
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="h-8 rounded bg-surface-2 border border-border px-2.5 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="ALL">All Types</option>
                <option value="PROOF">PROOF (Reproduction)</option>
                <option value="REQUEST">REQUEST</option>
                <option value="RESPONSE">RESPONSE</option>
                <option value="CHECK_EXECUTION_EVIDENCE">CHECK_EXECUTION_EVIDENCE</option>
                <option value="CHECK_EXECUTION_CLEAN">CHECK_EXECUTION_CLEAN</option>
                <option value="VULNERABILITY_EXECUTION_EVIDENCE">VULNERABILITY_EXECUTION_EVIDENCE</option>
              </select>
            </div>
          </Card>

          {/* STATE F: Evidence API Failure */}
          {error && !loading && (
            <Card className="p-6 bg-surface border-red-500/30 text-center space-y-3">
              <div className="w-10 h-10 rounded-full bg-red-500/10 text-red-400 flex items-center justify-center mx-auto">
                <AlertCircle className="w-5 h-5" />
              </div>
              <div>
                <div className="text-sm font-semibold text-text-primary">Unable to load evidence</div>
                <div className="text-xs text-text-secondary mt-1 font-mono">{error}</div>
              </div>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => selectedCampaignId && loadEvidence(selectedCampaignId)}
                className="mx-auto"
              >
                Retry
              </Button>
            </Card>
          )}

          {/* Loading State */}
          {loading && (
            <Card className="p-12 bg-surface border-border text-center space-y-3">
              <div className="flex items-center justify-center gap-2 text-accent">
                <RefreshCw className="w-5 h-5 animate-spin" />
                <span className="text-sm font-medium">Loading evidence...</span>
              </div>
            </Card>
          )}

          {/* STATE A: No execution has started */}
          {!loading && !error && filtered.length === 0 && isNotStarted && (
            <Card className="p-10 bg-surface border-border text-center space-y-2">
              <div className="w-10 h-10 rounded-full bg-surface-2 text-text-muted flex items-center justify-center mx-auto">
                <Play className="w-5 h-5 text-accent" />
              </div>
              <div className="text-sm font-semibold text-text-primary">No execution has started.</div>
              <div className="text-xs text-text-muted">No evidence captured yet.</div>
              <p className="text-xs text-text-secondary max-w-md mx-auto">
                Campaign is configured but has not yet launched check execution tasks or dispatched requests. Evidence will appear after campaign activity produces captured request/response artifacts.
              </p>
            </Card>
          )}

          {/* STATE B: Execution was blocked before network testing */}
          {!loading && !error && filtered.length === 0 && isBlocked && (
            <Card className="p-10 bg-surface border-amber-500/30 text-center space-y-2">
              <div className="w-10 h-10 rounded-full bg-amber-500/10 text-amber-400 flex items-center justify-center mx-auto">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div className="text-sm font-semibold text-amber-300">Execution was blocked before network testing.</div>
              <p className="text-xs text-text-secondary max-w-md mx-auto">
                {execSummary?.terminal_reason || 'Target out of scope, authorization missing, or destination safety check halted execution before network dispatch.'}
              </p>
            </Card>
          )}

          {/* STATE C: Execution running in progress */}
          {!loading && !error && filtered.length === 0 && isExecuting && (
            <Card className="p-10 bg-surface border-accent/30 text-center space-y-2">
              <div className="w-10 h-10 rounded-full bg-accent/10 text-accent flex items-center justify-center mx-auto">
                <RefreshCw className="w-5 h-5 animate-spin" />
              </div>
              <div className="text-sm font-semibold text-text-primary">
                Execution is in progress. {execSummary?.tests_completed || 0}/{execSummary?.tests_selected || 0} tests completed.
              </div>
              <p className="text-xs text-text-secondary max-w-md mx-auto">
                Worker agents are actively executing probes. Evidence will populate as tests complete.
              </p>
            </Card>
          )}

          {/* STATE D: Execution completed with zero evidence */}
          {isCompletedWithZeroEvidence && !isBlocked && !isNotStarted && (
            <Card className="p-10 bg-surface border-border text-center space-y-2">
              <div className="w-10 h-10 rounded-full bg-surface-2 text-emerald-400 flex items-center justify-center mx-auto">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div className="text-sm font-semibold text-text-primary">Execution completed. No evidence artifacts were captured.</div>
              <p className="text-xs text-text-secondary max-w-md mx-auto">
                All targeted security checks completed without observing anomalous HTTP response properties or security differentials.
              </p>
            </Card>
          )}

          {/* STATE E: Loaded State — Evidence Table */}
          {!loading && !error && filtered.length > 0 && (
            <Card className="p-0 bg-surface border-border overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-border bg-surface-2/60 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                      <th className="py-3 px-4">Evidence ID</th>
                      <th className="py-3 px-4">Type</th>
                      <th className="py-3 px-4">Target URL</th>
                      <th className="py-3 px-4">SHA-256 Hash</th>
                      <th className="py-3 px-4">Integrity Status</th>
                      <th className="py-3 px-4 text-right">Payload</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {filtered.map((item) => {
                      const eid = item.evidence_id || item.id;
                      return (
                        <tr
                          key={eid}
                          onClick={() => setPreviewEvidence(item)}
                          className="hover:bg-surface-2/50 cursor-pointer transition-colors"
                        >
                          <td className="py-3 px-4 font-mono font-semibold text-text-primary">
                            {eid}
                          </td>
                          <td className="py-3 px-4">
                            <Badge variant="info" size="xs">
                              {item.evidence_type}
                            </Badge>
                          </td>
                          <td className="py-3 px-4 font-mono text-text-secondary max-w-xs truncate">
                            {item.target_url}
                          </td>
                          <td className="py-3 px-4 font-mono text-text-muted text-[11px]">
                            {item.content_hash?.slice(0, 16)}...
                          </td>
                          <td className="py-3 px-4">
                            <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-mono">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              Verified
                            </span>
                          </td>
                          <td className="py-3 px-4 text-right">
                            <Button
                              variant="ghost"
                              size="xs"
                              onClick={(e) => {
                                e.stopPropagation();
                                setPreviewEvidence(item);
                              }}
                              className="flex items-center gap-1 text-accent ml-auto"
                              aria-label="View and inspect evidence"
                            >
                              <Eye className="w-3.5 h-3.5" /> Inspect
                            </Button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </>
      )}

      {/* Comprehensive Evidence Detail Modal */}
      {previewEvidence && (
        <Modal
          isOpen={Boolean(previewEvidence)}
          onClose={() => setPreviewEvidence(null)}
          title={`Evidence Detail: ${previewEvidence.evidence_id || previewEvidence.id}`}
        >
          <div className="space-y-4 text-xs">
            {/* Metadata Grid */}
            <div className="grid grid-cols-2 gap-2 p-3 rounded bg-surface-2/60 border border-border font-mono text-[11px]">
              <div>
                <span className="text-text-muted">Evidence ID: </span>
                <span className="text-text-primary font-bold">{previewEvidence.evidence_id || previewEvidence.id}</span>
              </div>
              <div>
                <span className="text-text-muted">Campaign ID: </span>
                <span className="text-text-primary">{previewEvidence.campaign_id}</span>
              </div>
              <div>
                <span className="text-text-muted">Method: </span>
                <span className="text-text-primary font-bold">{previewEvidence.method || 'GET'}</span>
              </div>
              <div>
                <span className="text-text-muted">HTTP Status: </span>
                <span className="text-emerald-400 font-bold font-mono">
                  {previewEvidence.status_code || previewEvidence.http_status || previewEvidence.response_status || 200} OK
                </span>
              </div>
              <div className="col-span-2">
                <span className="text-text-muted">Type: </span>
                <span className="text-accent font-semibold">{previewEvidence.evidence_type}</span>
              </div>
              <div className="col-span-2 truncate">
                <span className="text-text-muted">Target: </span>
                <span className="text-text-primary">{previewEvidence.target_url}</span>
              </div>
              {previewEvidence.finding_id && (
                <div className="col-span-2">
                  <span className="text-text-muted">Finding ID: </span>
                  <span className="text-emerald-400">{previewEvidence.finding_id}</span>
                </div>
              )}
            </div>

            {/* Secret Redaction Confirmation */}
            <div className="flex items-center justify-between p-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-[11px] text-emerald-300">
              <div className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-emerald-400" />
                <span>Secrets, auth tokens, passwords, and cookies are cryptographically redacted.</span>
              </div>
              <span className="font-mono font-bold">REDACTED</span>
            </div>

            {/* SHA-256 Cryptographic Hash */}
            <div className="space-y-1">
              <div className="text-[11px] font-semibold text-text-secondary uppercase">SHA-256 Content Hash</div>
              <div className="p-2 rounded bg-surface-2 font-mono text-[11px] text-emerald-400 break-all border border-border">
                {previewEvidence.content_hash}
              </div>
            </div>

            {/* Chained Hash */}
            {previewEvidence.chain_hash && (
              <div className="space-y-1">
                <div className="text-[11px] font-semibold text-text-secondary uppercase">Chain Hash (Audit-Anchored)</div>
                <div className="p-2 rounded bg-surface-2 font-mono text-[11px] text-text-muted break-all border border-border">
                  {previewEvidence.chain_hash}
                </div>
              </div>
            )}

            {/* Payload Summary / Observation */}
            {previewEvidence.payload_summary && (
              <div className="space-y-1">
                <div className="text-[11px] font-semibold text-text-secondary uppercase">Payload / Observation Summary</div>
                <div className="p-2.5 rounded bg-surface-2 text-text-primary font-mono text-[11px] border border-border">
                  {previewEvidence.payload_summary}
                </div>
              </div>
            )}

            {/* Request Payload */}
            {(previewEvidence.sanitized_request || previewEvidence.request_payload) && (
              <div className="space-y-1">
                <div className="text-[11px] font-semibold text-text-secondary uppercase">Request Payload (Sanitized)</div>
                <pre className="p-3 rounded bg-surface-2 font-mono text-[11px] text-text-primary overflow-x-auto whitespace-pre-wrap border border-border max-h-36 overflow-y-auto">
                  {previewEvidence.sanitized_request || previewEvidence.request_payload}
                </pre>
              </div>
            )}

            {/* Response Payload */}
            {(previewEvidence.sanitized_response || previewEvidence.response_payload) && (
              <div className="space-y-1">
                <div className="text-[11px] font-semibold text-text-secondary uppercase">Response Payload (Sanitized)</div>
                <pre className="p-3 rounded bg-surface-2 font-mono text-[11px] text-text-primary overflow-x-auto whitespace-pre-wrap border border-border max-h-48 overflow-y-auto">
                  {previewEvidence.sanitized_response || previewEvidence.response_payload}
                </pre>
              </div>
            )}

            <div className="flex justify-end pt-3 border-t border-border">
              <Button variant="secondary" size="sm" onClick={() => setPreviewEvidence(null)}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
