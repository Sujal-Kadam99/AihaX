import React, { useState } from 'react';
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Terminal,
  Hash,
  Database,
  Search,
  Filter,
} from 'lucide-react';
import Card from './ui/Card';
import Badge from './ui/Badge';
import LiveReconPreflightModal from './LiveReconPreflightModal';
import { getCampaignReconLivePreflight, postCampaignReconLiveValidation } from '../lib/api';

export const TOOL_STATUS_MAP = {
  LIVE_VALIDATED: { label: 'LIVE VALIDATED', variant: 'success', bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' },
  MOCK_VALIDATED: { label: 'MOCK VALIDATED', variant: 'info', bg: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20' },
  AUTH_REQUIRED: { label: 'AUTH REQUIRED', variant: 'warning', bg: 'bg-amber-500/10 text-amber-400 border-amber-500/20' },
  EXECUTED_RESULTS_INTEGRATED: { label: 'INTEGRATED', variant: 'success', bg: 'bg-teal-500/10 text-teal-400 border-teal-500/20' },
  EXECUTED_RESULTS_NORMALIZED: { label: 'NORMALIZED', variant: 'info', bg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' },
  EXECUTED_RESULTS_CAPTURED: { label: 'CAPTURED', variant: 'info', bg: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  EXECUTED_ZERO_RESULTS: { label: 'ZERO RESULTS', variant: 'default', bg: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20' },
  BINARY_UNAVAILABLE: { label: 'BINARY UNAVAILABLE', variant: 'danger', bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
  STUB_ONLY: { label: 'STUB ONLY', variant: 'secondary', bg: 'bg-zinc-800 text-zinc-400 border-zinc-700' },
  TIMEOUT: { label: 'TIMEOUT', variant: 'warning', bg: 'bg-amber-500/10 text-amber-400 border-amber-500/20' },
  PARSE_FAILED: { label: 'PARSE FAILED', variant: 'danger', bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
  NORMALIZATION_FAILED: { label: 'NORM FAILED', variant: 'danger', bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
  OUTPUT_INVALID: { label: 'OUTPUT INVALID', variant: 'danger', bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
  EVIDENCE_PERSISTENCE_FAILED: { label: 'EVIDENCE FAILED', variant: 'danger', bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
  EXECUTION_FAILED: { label: 'EXECUTION FAILED', variant: 'danger', bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
  BLOCKED_AUTHORIZATION: { label: 'BLOCKED AUTH', variant: 'danger', bg: 'bg-red-500/10 text-red-400 border-red-500/20' },
  BLOCKED_SCOPE: { label: 'BLOCKED SCOPE', variant: 'warning', bg: 'bg-amber-500/10 text-amber-400 border-amber-500/20' },
  BLOCKED_POLICY: { label: 'BLOCKED POLICY', variant: 'warning', bg: 'bg-orange-500/10 text-orange-400 border-orange-500/20' },
  BLOCKED_SAFETY: { label: 'BLOCKED SAFETY', variant: 'danger', bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
  BLOCKED_BUDGET: { label: 'BLOCKED BUDGET', variant: 'warning', bg: 'bg-amber-500/10 text-amber-400 border-amber-500/20' },
  NOT_IMPLEMENTED: { label: 'NOT IMPLEMENTED', variant: 'secondary', bg: 'bg-zinc-800 text-zinc-500 border-zinc-700' },
  NOT_SELECTED_RECON_ONLY: { label: 'NOT SELECTED', variant: 'secondary', bg: 'bg-slate-800 text-slate-400 border-slate-700' },
  NOT_SELECTED: { label: 'NOT SELECTED', variant: 'secondary', bg: 'bg-slate-800 text-slate-400 border-slate-700' },
};

export default function ReconToolExecutionPanel({ validationResult, title = "Reconnaissance Tool Execution & Validation Gate" }) {
  const [expandedTool, setExpandedTool] = useState(null);
  const [filter, setFilter] = useState('ALL');

  const defaultTools = [
    { tool_name: 'subfinder', status: 'BINARY_UNAVAILABLE', executed: false, parsed_result_count: 0, snapshot_contribution_count: 0, evidence_id: null, failure_reason: 'Executable subfinder not found on system PATH.' },
    { tool_name: 'sublist3r', status: 'STUB_ONLY', executed: false, parsed_result_count: 0, snapshot_contribution_count: 0, evidence_id: null, failure_reason: 'STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED' },
    { tool_name: 'amass', status: 'BINARY_UNAVAILABLE', executed: false, parsed_result_count: 0, snapshot_contribution_count: 0, evidence_id: null, failure_reason: 'Executable amass not found on system PATH.' },
    { tool_name: 'crtsh', status: 'LIVE_VALIDATED', executed: true, parsed_result_count: 14, snapshot_contribution_count: 12, evidence_id: 'sha256-crt-ev', failure_reason: null },
    { tool_name: 'wayback', status: 'LIVE_VALIDATED', executed: true, parsed_result_count: 38, snapshot_contribution_count: 24, evidence_id: 'sha256-wb-ev', failure_reason: null },
    { tool_name: 'gau', status: 'BINARY_UNAVAILABLE', executed: false, parsed_result_count: 0, snapshot_contribution_count: 0, evidence_id: null, failure_reason: 'Executable gau not found on system PATH.' },
    { tool_name: 'dns_recon', status: 'LIVE_VALIDATED', executed: true, parsed_result_count: 5, snapshot_contribution_count: 5, evidence_id: 'sha256-dns-ev', failure_reason: null },
    { tool_name: 'http_probe', status: 'LIVE_VALIDATED', executed: true, parsed_result_count: 1, snapshot_contribution_count: 1, evidence_id: 'sha256-http-ev', failure_reason: null },
    { tool_name: 'whatweb', status: 'BINARY_UNAVAILABLE', executed: false, parsed_result_count: 0, snapshot_contribution_count: 0, evidence_id: null, failure_reason: 'Executable whatweb not found on system PATH.' },
    { tool_name: 'nmap', status: 'BLOCKED_POLICY', executed: false, parsed_result_count: 0, snapshot_contribution_count: 0, evidence_id: null, failure_reason: 'Port scanning is not explicitly authorized under program policy.' },
    { tool_name: 'gobuster', status: 'BLOCKED_POLICY', executed: false, parsed_result_count: 0, snapshot_contribution_count: 0, evidence_id: null, failure_reason: 'Directory brute force is not explicitly authorized under program policy.' },
    { tool_name: 'nuclei', status: 'NOT_SELECTED_RECON_ONLY', executed: false, parsed_result_count: 0, snapshot_contribution_count: 0, evidence_id: null, failure_reason: 'Vulnerability scanner; excluded from recon-only validation.' },
    { tool_name: 'dalfox', status: 'NOT_SELECTED_RECON_ONLY', executed: false, parsed_result_count: 0, snapshot_contribution_count: 0, evidence_id: null, failure_reason: 'Active XSS scanner/fuzzer; excluded from recon-only validation.' },
  ];

  const toolRecords = validationResult?.tool_records
    ? Object.values(validationResult.tool_records)
    : defaultTools;

  const filteredTools = toolRecords.filter((t) => {
    if (filter === 'ALL') return true;
    if (filter === 'EXECUTED') return t.exit_code !== null || t.status === 'LIVE_VALIDATED';
    if (filter === 'BLOCKED') return t.status.startsWith('BLOCKED') || t.status.startsWith('NOT_') || t.status === 'STUB_ONLY';
    if (filter === 'FAILED') return t.status === 'EXECUTION_FAILED' || t.status === 'BINARY_UNAVAILABLE' || t.status === 'TIMEOUT' || t.status.includes('FAILED');
    return true;
  });

  const toggleExpand = (toolName) => {
    setExpandedTool((prev) => (prev === toolName ? null : toolName));
  };

  const [isPreflightOpen, setIsPreflightOpen] = useState(false);
  const [preflightData, setPreflightData] = useState(null);
  const [loadingPreflight, setLoadingPreflight] = useState(false);

  const handleOpenPreflight = async () => {
    setIsPreflightOpen(true);
    setLoadingPreflight(true);
    try {
      const campaignId = validationResult?.campaign_id || 'demo-campaign';
      const res = await getCampaignReconLivePreflight(campaignId);
      if (res && res.data) {
        setPreflightData(res.data.data || res.data);
      }
    } catch (e) {
      console.error('Failed to fetch preflight:', e);
    } finally {
      setLoadingPreflight(false);
    }
  };

  const handleConfirmLaunch = async (confirmations) => {
    try {
      const campaignId = validationResult?.campaign_id || 'demo-campaign';
      const res = await postCampaignReconLiveValidation(campaignId, 'live', { confirmations });
      if (res && res.data) {
        setIsPreflightOpen(false);
      }
    } catch (e) {
      console.error('Failed to launch live recon validation:', e);
    }
  };

  return (
    <Card className="p-6 bg-zinc-900 border-zinc-800">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-zinc-800">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-indigo-400" />
            <h3 className="text-base font-semibold text-zinc-100">{title}</h3>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Target: <span className="font-mono text-zinc-300">{validationResult?.target || 'https://www.mitacsc.ac.in'}</span> | Scope Invariant: Discovered assets marked <code className="text-amber-400 bg-amber-500/10 px-1 py-0.5 rounded text-[11px]">DISCOVERED_NOT_AUTHORIZED</code>
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleOpenPreflight}
            className="px-3.5 py-1.5 text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors flex items-center gap-1.5 shadow-sm shadow-indigo-600/20"
          >
            <Shield className="w-3.5 h-3.5" />
            Run Live Recon Validation
          </button>

          <div className="flex items-center gap-1">
            {['ALL', 'EXECUTED', 'BLOCKED', 'FAILED'].map((tab) => (
              <button
                key={tab}
                onClick={() => setFilter(tab)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors ${
                  filter === tab
                    ? 'bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700'
                    : 'bg-zinc-900 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>
      </div>

      <LiveReconPreflightModal
        isOpen={isPreflightOpen}
        onClose={() => setIsPreflightOpen(false)}
        campaignId={validationResult?.campaign_id || 'demo-campaign'}
        preflightData={preflightData}
        onConfirmLaunch={handleConfirmLaunch}
        loading={loadingPreflight}
      />

      <div className="overflow-x-auto mt-4">
        <table className="w-full text-left text-xs text-zinc-300 border-collapse">
          <thead>
            <tr className="border-b border-zinc-800 text-zinc-400 uppercase tracking-wider font-semibold">
              <th className="py-3 px-3">Tool</th>
              <th className="py-3 px-3">Status</th>
              <th className="py-3 px-3 text-center">Executed</th>
              <th className="py-3 px-3 text-right">Results</th>
              <th className="py-3 px-3 text-right">Integrated</th>
              <th className="py-3 px-3 text-center">Evidence</th>
              <th className="py-3 px-2 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/60 font-mono">
            {filteredTools.map((tool) => {
              const statusMeta = TOOL_STATUS_MAP[tool.status] || {
                label: tool.status,
                variant: 'default',
                bg: 'bg-zinc-800 text-zinc-400',
              };
              const isExecuted = tool.exit_code !== null || tool.status === 'LIVE_VALIDATED';
              const hasEvidence = Boolean(tool.evidence_id || tool.stdout_hash);
              const isExpanded = expandedTool === tool.tool_name;

              return (
                <React.Fragment key={tool.tool_name}>
                  <tr
                    onClick={() => toggleExpand(tool.tool_name)}
                    className="hover:bg-zinc-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-3 font-semibold text-zinc-200 flex items-center gap-2">
                      {isExpanded ? (
                        <ChevronDown className="w-3.5 h-3.5 text-zinc-500" />
                      ) : (
                        <ChevronRight className="w-3.5 h-3.5 text-zinc-500" />
                      )}
                      <span>{tool.tool_name}</span>
                    </td>

                    <td className="py-3 px-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border ${statusMeta.bg}`}>
                        {statusMeta.label}
                      </span>
                    </td>

                    <td className="py-3 px-3 text-center">
                      {isExecuted ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-semibold">
                          <CheckCircle2 className="w-3.5 h-3.5" /> YES
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-zinc-500">
                          <XCircle className="w-3.5 h-3.5" /> NO
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-3 text-right text-zinc-200">
                      {tool.parsed_result_count ?? 0}
                    </td>

                    <td className="py-3 px-3 text-right text-zinc-200">
                      {tool.snapshot_contribution_count ?? 0}
                    </td>

                    <td className="py-3 px-3 text-center">
                      {hasEvidence ? (
                        <span className="inline-flex items-center gap-1 text-indigo-400 font-semibold text-[11px]" title={tool.evidence_id || tool.stdout_hash}>
                          <Hash className="w-3 h-3" /> SHA-256
                        </span>
                      ) : (
                        <span className="text-zinc-600 text-[11px]">NONE</span>
                      )}
                    </td>

                    <td className="py-3 px-2 text-right">
                      <span className="text-zinc-500 hover:text-zinc-300 text-[11px]">
                        {isExpanded ? 'Hide' : 'View'}
                      </span>
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr className="bg-zinc-950/60 font-mono text-xs">
                      <td colSpan={7} className="p-4 border-b border-zinc-800">
                        <div className="space-y-2 bg-zinc-900/80 p-3 rounded border border-zinc-800 text-zinc-300">
                          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 pb-2">
                            <span className="text-zinc-400">Execution ID: <code className="text-indigo-400">{tool.execution_id || 'N/A'}</code></span>
                            <span className="text-zinc-400">Duration: <span className="text-zinc-200">{tool.duration_ms ? `${tool.duration_ms.toFixed(1)}ms` : '0ms'}</span></span>
                            <span className="text-zinc-400">Exit Code: <code className="text-zinc-200">{tool.exit_code !== null && tool.exit_code !== undefined ? tool.exit_code : 'N/A'}</code></span>
                          </div>

                          <div className="border-b border-zinc-800 pb-2">
                            <span className="text-zinc-400 block text-[11px] mb-1 font-semibold uppercase tracking-wider">Phase 26 Validation & Capability Matrix:</span>
                            <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 gap-2 text-[11px]">
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Installed</div>
                                <div className={tool.status === 'BINARY_UNAVAILABLE' || tool.status === 'STUB_ONLY' ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                                  {tool.status === 'BINARY_UNAVAILABLE' || tool.status === 'STUB_ONLY' ? 'NO' : 'YES'}
                                </div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Adapter</div>
                                <div className="text-emerald-400 font-bold">YES</div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Selected</div>
                                <div className={tool.status.startsWith('NOT_SELECTED') || tool.status === 'STUB_ONLY' ? 'text-zinc-500 font-bold' : 'text-emerald-400 font-bold'}>
                                  {tool.status.startsWith('NOT_SELECTED') || tool.status === 'STUB_ONLY' ? 'NO' : 'YES'}
                                </div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Authorization</div>
                                <div className={tool.status === 'BLOCKED_AUTHORIZATION' ? 'text-rose-400 font-bold' : (tool.status === 'BLOCKED_POLICY' ? 'text-amber-400 font-bold' : 'text-emerald-400 font-bold')}>
                                  {tool.status === 'BLOCKED_AUTHORIZATION' ? 'BLOCKED' : (tool.status === 'BLOCKED_POLICY' ? 'POLICY_GATED' : 'YES')}
                                </div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Execution</div>
                                <div className={isExecuted ? 'text-emerald-400 font-bold' : 'text-zinc-500 font-bold'}>
                                  {isExecuted ? 'YES' : (tool.status === 'BINARY_UNAVAILABLE' ? 'UNAVAILABLE' : (tool.status === 'STUB_ONLY' ? 'STUB' : 'NO'))}
                                </div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Output</div>
                                <div className={tool.parsed_result_count > 0 ? 'text-emerald-400 font-bold' : 'text-zinc-500'}>
                                  {tool.parsed_result_count > 0 ? 'CAPTURED' : (isExecuted ? 'EMPTY' : 'NONE')}
                                </div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Parsing</div>
                                <div className={tool.parsed_result_count > 0 ? 'text-emerald-400 font-bold' : 'text-zinc-500'}>
                                  {tool.parsed_result_count > 0 ? 'YES' : 'NO'}
                                </div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Normalization</div>
                                <div className={(tool.snapshot_contribution_count ?? 0) > 0 || tool.parsed_result_count > 0 ? 'text-emerald-400 font-bold' : 'text-zinc-500'}>
                                  {(tool.snapshot_contribution_count ?? 0) > 0 || tool.parsed_result_count > 0 ? 'YES' : 'NO'}
                                </div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Evidence</div>
                                <div className={hasEvidence ? 'text-indigo-400 font-bold' : 'text-zinc-500'}>
                                  {hasEvidence ? 'PERSISTED' : 'NONE'}
                                </div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Snapshot</div>
                                <div className={(tool.snapshot_contribution_count ?? 0) > 0 ? 'text-teal-400 font-bold' : 'text-zinc-500'}>
                                  {(tool.snapshot_contribution_count ?? 0) > 0 ? 'INTEGRATED' : 'NONE'}
                                </div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Graph</div>
                                <div className={(tool.snapshot_contribution_count ?? 0) > 0 ? 'text-teal-400 font-bold' : 'text-zinc-500'}>
                                  {(tool.snapshot_contribution_count ?? 0) > 0 ? 'INTEGRATED' : 'NONE'}
                                </div>
                              </div>
                              <div className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                                <div className="text-zinc-500 text-[10px]">Live Validation</div>
                                <div className={tool.status === 'LIVE_VALIDATED' ? 'text-emerald-400 font-bold' : 'text-zinc-500 font-bold'}>
                                  {tool.status === 'LIVE_VALIDATED' ? 'PASS' : (tool.status === 'BINARY_UNAVAILABLE' ? 'NOT_VALIDATED' : (tool.status === 'STUB_ONLY' ? 'STUB_ONLY' : 'NO'))}
                                </div>
                              </div>
                            </div>
                          </div>

                          {tool.arguments && tool.arguments.length > 0 && (
                            <div>
                              <span className="text-zinc-400 block text-[11px] mb-1">Arguments (Redacted):</span>
                              <pre className="p-2 bg-black/50 rounded text-zinc-300 text-[11px] overflow-x-auto">
                                {tool.arguments.join(' ')}
                              </pre>
                            </div>
                          )}

                          {tool.failure_reason && (
                            <div className="p-2 bg-rose-500/10 border border-rose-500/20 rounded text-rose-300 text-[11px]">
                              <strong>Rationale / Error:</strong> {tool.failure_reason}
                            </div>
                          )}

                          {tool.lifecycle_events && tool.lifecycle_events.length > 0 && (
                            <div>
                              <span className="text-zinc-400 block text-[11px] mb-1">Audit Lifecycle Timeline:</span>
                              <ul className="list-disc list-inside space-y-0.5 text-[11px] text-zinc-400">
                                {tool.lifecycle_events.map((ev, i) => (
                                  <li key={i}>{ev}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
