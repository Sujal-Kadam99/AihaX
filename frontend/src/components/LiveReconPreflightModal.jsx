import React, { useState, useEffect } from 'react';
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  ExternalLink,
  Lock,
  Zap,
  Info,
  Server,
  FileCheck,
} from 'lucide-react';
import Card from './ui/Card';
import Badge from './ui/Badge';
import { formatPortScope } from '../lib/portScope';

export default function LiveReconPreflightModal({
  isOpen,
  onClose,
  campaignId,
  preflightData,
  onConfirmLaunch,
  loading = false,
}) {
  const [confirmations, setConfirmations] = useState({
    authActive: false,
    targetCorrect: false,
    capabilitiesReviewed: false,
    liveTrafficAcknowledged: false,
  });

  const [submitting, setSubmitting] = useState(false);
  const [selectedCapabilities, setSelectedCapabilities] = useState([]);
  const [portScanProfile, setPortScanProfile] = useState('web_common');

  useEffect(() => {
    // Reset state when modal opens
    if (isOpen) {
      setConfirmations({
        authActive: false,
        targetCorrect: false,
        capabilitiesReviewed: false,
        liveTrafficAcknowledged: false,
      });
      setSelectedCapabilities([]);
      setPortScanProfile('web_common');
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const data = preflightData || {};
  const auth = data.authorization || {};
  const scope = data.scope || {};
  const safety = data.safety_budget || {};
  const toolMatrix = data.tool_matrix || [];

  const allConfirmed =
    confirmations.authActive &&
    confirmations.targetCorrect &&
    confirmations.capabilitiesReviewed &&
    confirmations.liveTrafficAcknowledged;

  const canLaunch = data.can_launch && allConfirmed && !submitting;

  const handleCheckboxChange = (key) => {
    setConfirmations((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleLaunch = async () => {
    if (!canLaunch) return;
    setSubmitting(true);
    try {
      await onConfirmLaunch(confirmations, selectedCapabilities, portScanProfile);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-zinc-900 border border-zinc-800 rounded-xl shadow-2xl overflow-hidden my-8">
        {/* Header */}
        <div className="p-6 border-b border-zinc-800 bg-gradient-to-r from-zinc-900 via-zinc-900 to-indigo-950/40 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/20 rounded-lg text-indigo-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-zinc-100">Live Recon Preflight & Confirmation</h2>
                <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  AUTHORIZED_LIVE_RECON
                </span>
              </div>
              <p className="text-xs text-zinc-400 mt-0.5">
                Target: <code className="text-indigo-300 font-mono">{data.target || 'N/A'}</code> | Campaign: <span className="text-zinc-200">{data.campaign_name || campaignId}</span>
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-zinc-200 text-xl font-bold p-1 rounded-lg hover:bg-zinc-800"
          >
            &times;
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 max-h-[70vh] overflow-y-auto font-sans">
          {/* Summary Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Authorization Status */}
            <div className="p-4 bg-zinc-950 rounded-lg border border-zinc-800">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Authorization</span>
                {auth.active ? (
                  <span className="inline-flex items-center gap-1 text-xs text-emerald-400 font-semibold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    <CheckCircle2 className="w-3.5 h-3.5" /> ACTIVE
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-xs text-rose-400 font-semibold bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
                    <XCircle className="w-3.5 h-3.5" /> {auth.status || 'MISSING / EXPIRED'}
                  </span>
                )}
              </div>
              <div className="text-xs space-y-1 font-mono text-zinc-300">
                <div>ID: <span className="text-indigo-400">{auth.authorization_id || 'N/A'}</span></div>
                <div>Operator: <span className="text-zinc-200">{auth.authorized_by || 'N/A'}</span></div>
                <div>Expires: <span className="text-zinc-400">{auth.expires_at ? auth.expires_at.slice(0, 19) : 'N/A'}</span></div>
                <div>Written scope reference: <span className={auth.reference_present ? 'text-emerald-400' : 'text-rose-400'}>{auth.reference_present ? 'RECORDED' : 'REQUIRED'}</span></div>
              </div>
            </div>

            {/* Scope & Mode */}
            <div className="p-4 bg-zinc-950 rounded-lg border border-zinc-800">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Scope Snapshot</span>
                <span className="inline-flex items-center gap-1 text-xs text-indigo-400 font-semibold bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                  VERIFIED
                </span>
              </div>
              <div className="text-xs space-y-1 font-mono text-zinc-300">
                <div>Hash: <span className="text-amber-400 font-mono text-[11px]">{scope.scope_hash ? `${scope.scope_hash.slice(0, 16)}...` : 'N/A'}</span></div>
                <div>Status: <span className="text-emerald-400 font-semibold">{scope.status || 'VALID'}</span></div>
                <div>Execution Mode: <span className="text-zinc-200">AUTHORIZED_LIVE</span></div>
              </div>
            </div>

            {/* Safety Constraints */}
            <div className="p-4 bg-zinc-950 rounded-lg border border-zinc-800">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Safety Budget</span>
                <span className="inline-flex items-center gap-1 text-xs text-amber-400 font-semibold bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                  CONSERVATIVE
                </span>
              </div>
              <div className="text-xs space-y-1 text-zinc-300 font-mono">
                <div>Max Concurrency: <span className="text-indigo-400">1</span></div>
                <div>Rate Limit: <span className="text-indigo-400 font-semibold">&le; 2 RPS</span></div>
                <div>HTTP Methods: <span className="text-zinc-200">GET / HEAD / OPTIONS</span></div>
              </div>
            </div>
          </div>

          {/* Active Tool Warnings */}
          <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-300 text-xs space-y-2">
            <div className="flex items-center gap-2 font-semibold text-amber-200">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span>Active Testing & Service Discovery Warning</span>
            </div>
            <p className="text-amber-300/90 leading-relaxed">
              <strong>Nmap</strong> scans only the selected ports that remain authorized after exclusions. <strong>Gobuster</strong> uses AihaX’s small bundled wordlist with two workers. Select either active recon capability below only when it is included in the client authorization. Nuclei and Dalfox vulnerability probes remain outside this recon run.
            </p>
          </div>

          <div className="p-4 bg-zinc-950 rounded-lg border border-zinc-800 space-y-3">
            <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider">Optional Active Recon</h3>
            <p className="text-xs text-zinc-400">Passive OSINT and low-impact HTTP discovery run under the campaign authorization. These active profiles stay off unless selected for this run.</p>
            {[
              ['service_discovery', 'Bounded service discovery (authorized TCP ports)'],
              ['content_discovery', 'Bounded path discovery (small wordlist, two workers)'],
            ].map(([capability, label]) => (
              <label key={capability} className="flex items-start gap-3 cursor-pointer text-xs text-zinc-300">
                <input
                  type="checkbox"
                  checked={selectedCapabilities.includes(capability)}
                  onChange={() => setSelectedCapabilities((prev) => prev.includes(capability)
                    ? prev.filter((item) => item !== capability)
                    : [...prev, capability])}
                  className="mt-0.5 rounded border-zinc-700 bg-zinc-900 text-indigo-600 focus:ring-indigo-500"
                />
                <span>{label}</span>
              </label>
            ))}
            <div className="text-xs text-zinc-400 font-mono" data-testid="port-scope-summary">
              Allowed: {formatPortScope(scope.allowed_ports)} · Excluded: {formatPortScope(scope.excluded_ports)}
            </div>
            {selectedCapabilities.includes('service_discovery') && (
              <div className="space-y-2 border-t border-zinc-800 pt-3">
                <label htmlFor="port-scan-profile" className="block text-xs text-zinc-300">Service scan port coverage</label>
                <select
                  id="port-scan-profile"
                  aria-label="Service scan port coverage"
                  value={portScanProfile}
                  onChange={(event) => setPortScanProfile(event.target.value)}
                  className="w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs text-zinc-200"
                >
                  <option value="web_common">Common web ports within scope (80, 443, 8080, 8443)</option>
                  <option value="all_authorized">All authorized TCP ports in scope</option>
                </select>
                <p className="text-[11px] text-amber-300/90">
                  The selected profile is intersected with Allowed Ports and then Excluded Ports are removed. All authorized ports can generate more probes; select it only when the client policy explicitly permits that coverage.
                </p>
              </div>
            )}
          </div>

          {/* Tool Matrix Preflight Table */}
          <div>
            <h3 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider mb-3">Toolchain Preflight Matrix</h3>
            <div className="overflow-x-auto border border-zinc-800 rounded-lg">
              <table className="w-full text-left text-xs text-zinc-300 border-collapse">
                <thead>
                  <tr className="bg-zinc-950 text-zinc-400 border-b border-zinc-800 uppercase font-semibold text-[11px]">
                    <th className="py-2.5 px-3">Tool</th>
                    <th className="py-2.5 px-3">Capability Class</th>
                    <th className="py-2.5 px-3 text-center">Binary</th>
                    <th className="py-2.5 px-3 text-center">Authorization</th>
                    <th className="py-2.5 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800 font-mono text-[11px]">
                  {toolMatrix.map((item) => (
                    <tr key={item.tool_name} className="hover:bg-zinc-800/30">
                      <td className="py-2 px-3 font-semibold text-zinc-200">{item.tool_name}</td>
                      <td className="py-2 px-3 text-zinc-400">{item.capability_class}</td>
                      <td className="py-2 px-3 text-center">
                        {item.installed ? (
                          <span className="text-emerald-400 font-semibold">YES</span>
                        ) : (
                          <span className="text-rose-400 font-semibold">NO</span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-center">
                        {item.auth_permitted ? (
                          <span className="text-emerald-400 font-semibold">ALLOWED</span>
                        ) : (
                          <span className="text-rose-400 font-semibold">BLOCKED</span>
                        )}
                      </td>
                      <td className="py-2 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          item.status === 'AVAILABLE' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                          item.status === 'AUTH_REQUIRED' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
                          item.status === 'STUB_ONLY' ? 'bg-zinc-800 text-zinc-400 border-zinc-700' :
                          'bg-rose-500/10 text-rose-400 border-rose-500/20'
                        }`}>
                          {item.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Four Mandatory Operator Confirmation Checkboxes */}
          <div className="p-4 bg-zinc-950 rounded-lg border border-zinc-800 space-y-3">
            <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider mb-2">Operator Confirmations Required</h3>

            <label className="flex items-start gap-3 cursor-pointer text-xs text-zinc-300">
              <input
                type="checkbox"
                checked={confirmations.authActive}
                onChange={() => handleCheckboxChange('authActive')}
                className="mt-0.5 rounded border-zinc-700 bg-zinc-900 text-indigo-600 focus:ring-indigo-500"
              />
              <span>I confirm that this campaign has an active and valid <code>AuthorizationRecord</code>.</span>
            </label>

            <label className="flex items-start gap-3 cursor-pointer text-xs text-zinc-300">
              <input
                type="checkbox"
                checked={confirmations.targetCorrect}
                onChange={() => handleCheckboxChange('targetCorrect')}
                className="mt-0.5 rounded border-zinc-700 bg-zinc-900 text-indigo-600 focus:ring-indigo-500"
              />
              <span>I confirm that the displayed target (<code className="text-indigo-300">{data.target}</code>) matches the authorized scope.</span>
            </label>

            <label className="flex items-start gap-3 cursor-pointer text-xs text-zinc-300">
              <input
                type="checkbox"
                checked={confirmations.capabilitiesReviewed}
                onChange={() => handleCheckboxChange('capabilitiesReviewed')}
                className="mt-0.5 rounded border-zinc-700 bg-zinc-900 text-indigo-600 focus:ring-indigo-500"
              />
              <span>I confirm that I have reviewed the permitted capability classes and safety budget rules.</span>
            </label>

            <label className="flex items-start gap-3 cursor-pointer text-xs text-zinc-300">
              <input
                type="checkbox"
                checked={confirmations.liveTrafficAcknowledged}
                onChange={() => handleCheckboxChange('liveTrafficAcknowledged')}
                className="mt-0.5 rounded border-zinc-700 bg-zinc-900 text-indigo-600 focus:ring-indigo-500"
              />
              <span>I understand that initiating live reconnaissance will generate authorized network traffic against the target.</span>
            </label>
          </div>
        </div>

        {/* Modal Footer Actions */}
        <div className="p-6 border-t border-zinc-800 bg-zinc-950 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-zinc-400 hover:text-zinc-200 bg-zinc-800 hover:bg-zinc-700 rounded-lg transition-colors"
          >
            Cancel
          </button>

          <button
            onClick={handleLaunch}
            disabled={!canLaunch}
            className={`px-5 py-2 text-xs font-bold rounded-lg transition-all flex items-center gap-2 ${
              canLaunch
                ? 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/20'
                : 'bg-zinc-800 text-zinc-500 cursor-not-allowed border border-zinc-700'
            }`}
          >
            <Shield className="w-4 h-4" />
            {submitting ? 'Initiating Validation Run...' : 'Confirm & Run Authorized Live Recon'}
          </button>
        </div>
      </div>
    </div>
  );
}
