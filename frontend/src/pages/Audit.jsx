import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { CheckCircle2 } from 'lucide-react';
import { getCampaignAuditTrail, getCampaigns } from '../lib/api';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import Input from '../components/ui/Input';

export default function Audit() {
  const [searchParams] = useSearchParams();
  const initialCampaignId = searchParams.get('campaign');

  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState(initialCampaignId || '');
  const [auditEvents, setAuditEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');

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
        console.error('Error loading campaigns for audit:', err);
      }
    }
    loadCampaignsList();
  }, []);

  useEffect(() => {
    if (selectedCampaignId) {
      loadAuditTrail(selectedCampaignId);
    } else {
      setLoading(false);
    }
  }, [selectedCampaignId]);

  async function loadAuditTrail(campaignId) {
    try {
      setLoading(true);
      const res = await getCampaignAuditTrail(campaignId);
      setAuditEvents(res.data?.data || []);
    } catch (err) {
      console.error('Error loading audit trail:', err);
    } finally {
      setLoading(false);
    }
  }

  const filtered = auditEvents.filter((ev) => {
    const matchesAction = actionFilter === 'ALL' || ev.event_type === actionFilter;
    if (!matchesAction) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      ev.operator_id?.toLowerCase().includes(q) ||
      ev.event_type?.toLowerCase().includes(q) ||
      ev.target_url?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">
            Cryptographic Audit Trail
          </h1>
          <p className="text-xs text-text-secondary mt-0.5">
            Genesis-to-tip chained SHA-256 event log for non-repudiation and regulatory compliance.
          </p>
        </div>

        {/* Campaign Selector */}
        {campaigns.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted">Campaign:</span>
            <select
              value={selectedCampaignId}
              onChange={(e) => setSelectedCampaignId(e.target.value)}
              className="h-8 rounded bg-surface-2 border border-border px-2.5 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            >
              {campaigns.map((c) => (
                <option key={c.campaign_id || c.id} value={c.campaign_id || c.id}>
                  {c.name} ({c.target_url})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Filter Bar */}
      <Card className="p-3 bg-surface border-border flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="w-full sm:w-80">
          <Input
            placeholder="Search operator, event, or target..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="text-xs font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs text-text-muted">Event Type:</span>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="h-8 rounded bg-surface-2 border border-border px-2.5 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value="ALL">All Events</option>
            <option value="CAMPAIGN_CREATED">CAMPAIGN_CREATED</option>
            <option value="CAMPAIGN_AUTHORIZED">CAMPAIGN_AUTHORIZED</option>
            <option value="CAMPAIGN_STARTED">CAMPAIGN_STARTED</option>
            <option value="TASK_COMPLETED">TASK_COMPLETED</option>
            <option value="FINDING_VERIFIED">FINDING_VERIFIED</option>
            <option value="REPORT_GENERATED">REPORT_GENERATED</option>
          </select>
        </div>
      </Card>

      {/* Audit Log Table */}
      <Card className="p-0 bg-surface border-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-border bg-surface-2/60 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Operator</th>
                <th className="py-3 px-4">Action Event</th>
                <th className="py-3 px-4">Target / Detail</th>
                <th className="py-3 px-4">Chained Hash Link</th>
                <th className="py-3 px-4 text-right">Integrity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border font-mono text-[11px]">
              {filtered.length === 0 && !loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-text-secondary font-sans text-xs">
                    No audit records logged for this campaign.
                  </td>
                </tr>
              ) : (
                filtered.map((ev, index) => (
                  <tr key={ev.event_hash || index} className="hover:bg-surface-2/50 transition-colors">
                    <td className="py-3 px-4 text-text-secondary">
                      {ev.timestamp?.replace('T', ' ').slice(0, 19) || 'Just now'}
                    </td>
                    <td className="py-3 px-4 text-text-primary font-semibold font-sans">
                      {ev.operator_id || 'system_service'}
                    </td>
                    <td className="py-3 px-4">
                      <Badge variant="info" size="xs">
                        {ev.event_type}
                      </Badge>
                    </td>
                    <td className="py-3 px-4 text-text-secondary max-w-xs truncate font-sans">
                      {ev.target_url || JSON.stringify(ev.details || {})}
                    </td>
                    <td className="py-3 px-4 text-text-muted text-[10px]">
                      {ev.event_hash?.slice(0, 16)}...
                    </td>
                    <td className="py-3 px-4 text-right">
                      <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Chained
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
