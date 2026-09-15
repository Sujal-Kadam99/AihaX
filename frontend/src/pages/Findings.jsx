import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Eye, RefreshCw, Filter } from 'lucide-react';
import { getCampaignFindings, getFindings, getCampaigns } from '../lib/api';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import Input from '../components/ui/Input';
import Button from '../components/ui/Button';

const SEVERITY_COLORS = {
  critical: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  medium: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
  low: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  info: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
};

export default function Findings() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const initialCampaignId = searchParams.get('campaign') || searchParams.get('id') || '';

  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState(initialCampaignId);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  useEffect(() => {
    async function loadCampaignsList() {
      try {
        const res = await getCampaigns();
        const list = res.data?.data || res.data || [];
        setCampaigns(list);
        if (list.length > 0 && !selectedCampaignId) {
          const firstId = list[0].campaign_id || list[0].id;
          setSelectedCampaignId(firstId);
        }
      } catch (err) {
        console.error('Error fetching campaigns list:', err);
      }
    }
    loadCampaignsList();
  }, []);

  useEffect(() => {
    loadFindings();
  }, [selectedCampaignId, severityFilter, statusFilter]);

  async function loadFindings() {
    try {
      setLoading(true);
      if (selectedCampaignId && selectedCampaignId !== 'ALL') {
        const params = {};
        if (severityFilter !== 'ALL') params.severity = severityFilter;
        if (statusFilter !== 'ALL') params.status = statusFilter;
        const res = await getCampaignFindings(selectedCampaignId, params);
        const raw = res.data?.data ?? res.data ?? [];
        setFindings(Array.isArray(raw) ? raw : []);
      } else {
        const res = await getFindings('all');
        const list = res.data?.data || res.data || [];
        setFindings(Array.isArray(list) ? list : []);
      }
    } catch (err) {
      console.error('Error fetching findings:', err);
      setFindings([]);
    } finally {
      setLoading(false);
    }
  }

  const filtered = findings.filter((f) => {
    if (severityFilter !== 'ALL' && f.severity?.toLowerCase() !== severityFilter.toLowerCase()) {
      return false;
    }
    if (statusFilter !== 'ALL') {
      const vStatus = (f.verification_status || f.verdict || '').toUpperCase();
      const disp = (f.finding_disposition || '').toUpperCase();
      if (statusFilter === 'VALIDATED' && !vStatus.includes('VALIDATED') && !vStatus.includes('VERIFIED') && disp !== 'VALIDATED' && disp !== 'VULNERABILITY') return false;
      if (statusFilter === 'HARDENING_ONLY' && disp !== 'HARDENING_ONLY' && !vStatus.includes('HARDENING')) return false;
      if (statusFilter === 'INCONCLUSIVE' && disp !== 'INCONCLUSIVE' && !vStatus.includes('INCONCLUSIVE')) return false;
      if (statusFilter === 'FALSE_POSITIVE' && disp !== 'FALSE_POSITIVE' && !f.false_positive && !vStatus.includes('REJECTED')) return false;
      if (statusFilter === 'NOT_BOUNTY_ELIGIBLE' && disp !== 'NOT_BOUNTY_ELIGIBLE') return false;
      if (statusFilter === 'CANDIDATE' && !vStatus.includes('CANDIDATE')) return false;
    }
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.title?.toLowerCase().includes(q) ||
      f.vuln_type?.toLowerCase().includes(q) ||
      f.affected_url?.toLowerCase().includes(q) ||
      f.category?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">
            Security Findings Intelligence
          </h1>
          <p className="text-xs text-text-secondary mt-0.5">
            {selectedCampaignId && selectedCampaignId !== 'ALL'
              ? `Findings for selected assessment target (${filtered.length} visible)`
              : `Deterministic verified vulnerabilities and observed candidate findings (${filtered.length} total)`}
          </p>
        </div>

        {/* Campaign Selector & Refresh */}
        <div className="flex items-center gap-2 flex-wrap">
          {campaigns.length > 0 && (
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-text-muted">Campaign:</span>
              <select
                value={selectedCampaignId}
                onChange={(e) => {
                  const val = e.target.value;
                  setSelectedCampaignId(val);
                  if (val && val !== 'ALL') {
                    setSearchParams({ campaign: val });
                  } else {
                    setSearchParams({});
                  }
                }}
                className="h-8 rounded bg-surface-2 border border-border px-2.5 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="ALL">All Campaigns</option>
                {campaigns.map((c) => {
                  const cid = c.campaign_id || c.id;
                  const cname = c.campaign_name || c.name || 'Assessment';
                  return (
                    <option key={cid} value={cid}>
                      {cname} ({c.target_url})
                    </option>
                  );
                })}
              </select>
            </div>
          )}

          <Button
            variant="secondary"
            size="xs"
            onClick={loadFindings}
            loading={loading}
            className="flex items-center gap-1"
          >
            <RefreshCw className="w-3 h-3" />
            <span>Refresh</span>
          </Button>
        </div>
      </div>

      {/* Severity Quick Filters & Search Bar */}
      <Card className="p-3 bg-surface border-border flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="w-full sm:w-80">
          <Input
            placeholder="Search by title, check ID, or target..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="text-xs"
          />
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto flex-wrap">
          <div className="flex items-center gap-1 bg-surface-2 p-1 rounded border border-border text-xs">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded font-medium transition-colors ${
                  severityFilter === sev
                    ? 'bg-accent/20 text-accent font-semibold'
                    : 'text-text-secondary hover:text-text-primary'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="h-8 rounded bg-surface-2 border border-border px-2.5 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            >
              <option value="ALL">All States</option>
              <option value="VALIDATED">VALIDATED (Vulnerability)</option>
              <option value="HARDENING_ONLY">HARDENING ONLY</option>
              <option value="INCONCLUSIVE">INCONCLUSIVE</option>
              <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
              <option value="NOT_BOUNTY_ELIGIBLE">NOT BOUNTY ELIGIBLE</option>
              <option value="CANDIDATE">CANDIDATE (Unverified)</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Findings Table */}
      <Card className="p-0 bg-surface border-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-border bg-surface-2/60 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Vulnerability Title</th>
                <th className="py-3 px-4">Target URL</th>
                <th className="py-3 px-4">Verification State</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.length === 0 && !loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-text-secondary">
                    No findings matching the selected filters.
                  </td>
                </tr>
              ) : (
                filtered.map((finding) => {
                  const sevLower = (finding.severity || 'info').toLowerCase();
                  const sevClass = SEVERITY_COLORS[sevLower] || SEVERITY_COLORS.info;
                  const isVerified = finding.verification_status === 'VERIFIED' || finding.verdict === 'Verified';

                  return (
                    <tr
                      key={finding.id}
                      onClick={() => navigate(`/findings/${finding.id}`)}
                      className="hover:bg-surface-2/50 cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono border ${sevClass}`}
                        >
                          {finding.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-semibold text-text-primary hover:text-accent">
                          {finding.title}
                        </div>
                        <div className="text-[11px] font-mono text-text-muted mt-0.5">
                          {finding.vuln_type}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-text-secondary max-w-xs truncate">
                        {finding.affected_url}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {(() => {
                            const disp = (finding.finding_disposition || finding.verification_status || finding.verdict || 'INCONCLUSIVE').toUpperCase();
                            const bVariant = (disp === 'VALIDATED' || disp === 'EXPLOITABLE' || disp === 'VERIFIED')
                              ? 'success'
                              : disp === 'HARDENING_ONLY'
                              ? 'info'
                              : (disp === 'FALSE_POSITIVE' || disp === 'REJECTED')
                              ? 'danger'
                              : (disp === 'CANDIDATE' || disp === 'DETECTED')
                              ? 'warning'
                              : 'secondary';
                            return (
                              <Badge variant={bVariant} size="xs">
                                {disp}
                              </Badge>
                            );
                          })()}
                          {finding.human_review_status === 'APPROVED' && (
                            <Badge variant="success" size="xs">
                              APPROVED
                            </Badge>
                          )}
                          {finding.duplicate_of && (
                            <Badge variant="secondary" size="xs">
                              DUP
                            </Badge>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-text-primary font-medium">
                        {finding.confidence || 0}%
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/findings/${finding.id}`);
                          }}
                          className="flex items-center gap-1 text-accent ml-auto"
                        >
                          <Eye className="w-3.5 h-3.5" /> Details
                        </Button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
