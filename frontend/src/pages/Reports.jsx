import { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  ShieldCheck,
  RefreshCw,
  AlertCircle,
} from 'lucide-react';
import { getCampaigns, downloadCampaignReport, generateCampaignReports } from '../lib/api';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import { useToast } from '../hooks/useToast';

export default function Reports() {
  const { addToast } = useToast();
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [downloadingId, setDownloadingId] = useState(null);
  const [generatingId, setGeneratingId] = useState(null);

  useEffect(() => {
    loadCampaignReports();
  }, []);

  async function loadCampaignReports() {
    try {
      setLoading(true);
      setError(null);
      const res = await getCampaigns();
      const list = res.data?.data || res.data || [];
      setCampaigns(list);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Could not load campaigns catalog.';
      setError(msg);
      console.error('Error loading reports:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleGenerate(campaignId) {
    try {
      setGeneratingId(campaignId);
      const res = await generateCampaignReports(campaignId);
      const count = res.data?.verified_findings_count ?? 0;
      addToast({
        title: 'Report Manifest Ready',
        message: `Generated bug bounty report summary covering ${count} verified findings.`,
        type: 'success',
      });
      await loadCampaignReports();
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Report generation failed.';
      addToast({
        title: 'Generation Failed',
        message: msg,
        type: 'error',
      });
    } finally {
      setGeneratingId(null);
    }
  }

  async function handleDownload(campaignId, campaignName) {
    try {
      setDownloadingId(campaignId);
      const res = await downloadCampaignReport(campaignId);

      // Validate that response data is a valid Blob/ArrayBuffer
      const blob = res.data instanceof Blob ? res.data : new Blob([res.data], { type: 'application/pdf' });

      if (blob.size === 0) {
        throw new Error('Received an empty report file from backend.');
      }

      // Verify the PDF magic header (%PDF-)
      const headerText = await blob.slice(0, 5).text();
      if (!headerText.startsWith('%PDF')) {
        // Attempt to extract JSON error message
        let errorDetail = 'Invalid PDF stream received.';
        try {
          const fullText = await blob.text();
          const parsed = JSON.parse(fullText);
          if (parsed.detail) errorDetail = parsed.detail;
        } catch {
          // not JSON
        }
        throw new Error(errorDetail);
      }

      // Create download trigger
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const safeName = (campaignName || 'Report').replace(/[^a-zA-Z0-9-_]/g, '_');
      a.download = `AihaX-${safeName}-${campaignId.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      addToast({
        title: 'Report Downloaded',
        message: 'Report downloaded successfully.',
        type: 'success',
      });
    } catch (err) {
      let statusDetail = err.message;
      if (err.response?.status === 404) {
        statusDetail = 'Report artifact not found on backend (404).';
      } else if (err.response?.status === 409) {
        statusDetail = 'Report generation conflict (409).';
      } else if (err.response?.status === 422) {
        statusDetail = 'Unprocessable report request (422).';
      } else if (err.response?.status === 500) {
        statusDetail = 'Backend failed to render PDF report (500).';
      }

      addToast({
        title: 'Download Failed',
        message: statusDetail,
        type: 'error',
      });
    } finally {
      setDownloadingId(null);
    }
  }

  const filtered = campaigns.filter((c) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return c.name?.toLowerCase().includes(q) || c.target_url?.toLowerCase().includes(q);
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">
            Security & Bug-Bounty Reports
          </h1>
          <p className="text-xs text-text-secondary mt-0.5">
            Audit-grade, verified-only vulnerability reports in Executive, Bug Bounty, and Technical formats.
          </p>
        </div>

        <Button
          variant="secondary"
          size="sm"
          onClick={loadCampaignReports}
          loading={loading}
          className="flex items-center gap-1.5 self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </Button>
      </div>

      {/* Filter Bar */}
      <Card className="p-3 bg-surface border-border flex items-center justify-between">
        <div className="w-full sm:w-80">
          <Input
            placeholder="Search reports by target or campaign name..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="text-xs"
          />
        </div>
        <div className="text-xs font-mono text-text-muted hidden sm:block">
          Evidence Anchoring: SHA-256 Chained
        </div>
      </Card>

      {/* Error Banner */}
      {error && (
        <div className="p-3 rounded bg-red-500/10 border border-red-500/30 flex items-center justify-between text-xs text-red-400">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
          <Button variant="secondary" size="xs" onClick={loadCampaignReports}>
            Retry
          </Button>
        </div>
      )}

      {/* Reports Table */}
      <Card className="p-0 bg-surface border-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-border bg-surface-2/60 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                <th className="py-3 px-4">Report / Campaign</th>
                <th className="py-3 px-4">Target Scope</th>
                <th className="py-3 px-4">Mode</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Integrity Anchor</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading && campaigns.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-text-secondary">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-accent" />
                      <span>Loading reports...</span>
                    </div>
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-text-secondary">
                    No reports generated yet.
                  </td>
                </tr>
              ) : (
                filtered.map((camp) => {
                  const campId = camp.campaign_id || camp.id;
                  const isDownloading = downloadingId === campId;
                  const isGenerating = generatingId === campId;

                  return (
                    <tr key={campId} className="hover:bg-surface-2/50 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-semibold text-text-primary flex items-center gap-1.5">
                          <FileText className="w-4 h-4 text-accent flex-shrink-0" />
                          <span>{camp.name}</span>
                        </div>
                        <div className="text-[11px] font-mono text-text-muted mt-0.5">
                          ID: {campId?.slice(0, 8)}...
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-text-secondary">
                        {camp.target_url}
                      </td>
                      <td className="py-3 px-4 font-mono text-text-primary">
                        {camp.mode}
                      </td>
                      <td className="py-3 px-4">
                        <Badge
                          variant={
                            camp.status === 'COMPLETED'
                              ? 'success'
                              : camp.status === 'RUNNING'
                              ? 'info'
                              : 'secondary'
                          }
                          size="xs"
                        >
                          {camp.status}
                        </Badge>
                      </td>
                      <td className="py-3 px-4">
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-mono">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          Verified
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <Button
                            variant="secondary"
                            size="xs"
                            loading={isGenerating}
                            onClick={() => handleGenerate(campId)}
                            className="flex items-center gap-1"
                          >
                            <RefreshCw className="w-3 h-3" />
                            <span>Generate</span>
                          </Button>
                          <Button
                            variant="primary"
                            size="xs"
                            loading={isDownloading}
                            disabled={isGenerating}
                            onClick={() => handleDownload(campId, camp.name)}
                            className="flex items-center gap-1"
                          >
                            <Download className="w-3.5 h-3.5" />
                            <span>Download PDF</span>
                          </Button>
                        </div>
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
