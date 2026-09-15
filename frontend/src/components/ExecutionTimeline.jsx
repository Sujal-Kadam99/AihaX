import React, { useState, useEffect } from 'react';
import {
  Clock,
  CheckCircle2,
  AlertCircle,
  ShieldAlert,
  Play,
  FileCheck,
  Search,
  Database,
  RefreshCw,
  Filter,
} from 'lucide-react';
import { getCampaignTimeline } from '../lib/api';
import Card from './ui/Card';
import Badge from './ui/Badge';
import Button from './ui/Button';

export default function ExecutionTimeline({ campaignId, onSelectEvidence, onSelectFinding }) {
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterType, setFilterType] = useState('ALL');

  useEffect(() => {
    if (campaignId) {
      loadTimeline(campaignId);
    }
  }, [campaignId]);

  async function loadTimeline(cid) {
    try {
      setLoading(true);
      setError(null);
      const res = await getCampaignTimeline(cid);
      const raw = res.data?.data || res.data || [];
      const list = Array.isArray(raw) ? raw : (Array.isArray(raw?.items) ? raw.items : []);
      setTimeline(list);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Unable to load execution timeline';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  const filtered = timeline.filter((e) => {
    if (filterType === 'ALL') return true;
    if (filterType === 'TESTS') return e.event_type.includes('TEST') || e.event_type.includes('REQUEST');
    if (filterType === 'EVIDENCE') return e.event_type.includes('EVIDENCE') || e.event_type.includes('VERIF');
    if (filterType === 'BLOCKED') return e.event_type.startsWith('BLOCKED') || e.event_type.includes('ERROR');
    return true;
  });

  const getEventBadge = (eventType, status) => {
    if (eventType.startsWith('BLOCKED_')) {
      return <Badge variant="warning" size="xs">{eventType}</Badge>;
    }
    if (eventType.includes('ERROR')) {
      return <Badge variant="danger" size="xs">{eventType}</Badge>;
    }
    if (eventType.includes('EVIDENCE_CAPTURED') || eventType.includes('FINDING_CREATED')) {
      return <Badge variant="accent" size="xs">{eventType}</Badge>;
    }
    if (eventType.includes('COMPLETED') || status === 'SUCCESS') {
      return <Badge variant="success" size="xs">{eventType}</Badge>;
    }
    return <Badge variant="info" size="xs">{eventType}</Badge>;
  };

  return (
    <Card className="p-4 bg-surface border-border space-y-4">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-accent" />
          <h3 className="text-xs font-bold text-text-primary uppercase tracking-wider">
            Deterministic Execution Timeline ({filtered.length})
          </h3>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-surface-2 p-1 rounded border border-border text-[11px]">
            {['ALL', 'TESTS', 'EVIDENCE', 'BLOCKED'].map((f) => (
              <button
                key={f}
                onClick={() => setFilterType(f)}
                className={`px-2 py-0.5 rounded font-medium transition-colors ${
                  filterType === f
                    ? 'bg-accent/20 text-accent font-semibold'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
          <Button
            variant="ghost"
            size="xs"
            onClick={() => loadTimeline(campaignId)}
            className="flex items-center gap-1"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="p-8 text-center space-y-2 text-text-muted">
          <RefreshCw className="w-5 h-5 animate-spin mx-auto text-accent" />
          <p className="text-xs">Loading execution timeline...</p>
        </div>
      )}

      {/* Error State */}
      {error && !loading && (
        <div className="p-6 text-center space-y-2 bg-red-500/10 border border-red-500/30 rounded">
          <AlertCircle className="w-5 h-5 text-red-400 mx-auto" />
          <div className="text-xs font-semibold text-text-primary">Failed to load timeline</div>
          <p className="text-[11px] text-text-secondary">{error}</p>
          <Button size="xs" variant="secondary" onClick={() => loadTimeline(campaignId)} className="mx-auto mt-2">
            Retry
          </Button>
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && filtered.length === 0 && (
        <div className="p-8 text-center space-y-2 text-text-muted">
          <Clock className="w-6 h-6 mx-auto opacity-50" />
          <div className="text-xs font-semibold text-text-primary">No lifecycle events recorded yet.</div>
          <p className="text-[11px] text-text-secondary">
            Lifecycle events will appear as execution stages are reached.
          </p>
        </div>
      )}

      {/* Timeline Event Stream */}
      {!loading && !error && filtered.length > 0 && (
        <div className="space-y-2.5 max-h-[450px] overflow-y-auto pr-1">
          {filtered.map((event, idx) => (
            <div
              key={event.id || idx}
              className="p-2.5 rounded bg-surface-2/40 border border-border/80 hover:bg-surface-2/70 transition-colors text-xs space-y-1"
            >
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-1.5 font-mono text-[11px] text-text-muted">
                  <span>{new Date(event.timestamp).toLocaleTimeString()}</span>
                  &bull;
                  {getEventBadge(event.event_type, event.status)}
                </div>
                {event.event_hash && (
                  <span className="font-mono text-[10px] text-text-muted opacity-70" title={`Event SHA-256: ${event.event_hash}`}>
                    #{event.event_hash.slice(0, 8)}
                  </span>
                )}
              </div>

              {/* Event Body Details */}
              <div className="flex items-start justify-between gap-3 pt-0.5">
                <div className="space-y-0.5 font-mono text-[11px]">
                  {event.check_id && (
                    <div className="font-semibold text-text-primary flex items-center gap-1.5">
                      <Play className="w-3 h-3 text-accent shrink-0" />
                      {event.check_id}
                      {event.test_id && <span className="text-text-muted font-normal">({event.test_id})</span>}
                    </div>
                  )}
                  {event.target_url && (
                    <div className="text-text-secondary truncate max-w-md">
                      {event.target_url}
                    </div>
                  )}
                  {event.reason && (
                    <div className={`text-[11px] mt-1 ${event.event_type.startsWith('BLOCKED_') ? 'text-amber-400 font-medium' : 'text-text-muted'}`}>
                      {event.reason}
                    </div>
                  )}
                </div>

                {/* Direct Action Chips */}
                <div className="flex items-center gap-1.5 shrink-0">
                  {event.evidence_id && (
                    <button
                      onClick={() => onSelectEvidence && onSelectEvidence(event.evidence_id)}
                      className="px-2 py-0.5 rounded bg-accent/15 border border-accent/30 text-accent hover:bg-accent/25 text-[10px] font-mono flex items-center gap-1 transition-colors"
                      title="View Evidence Artifact"
                    >
                      <Database className="w-3 h-3" />
                      {event.evidence_id.slice(0, 10)}
                    </button>
                  )}
                  {event.finding_id && (
                    <button
                      onClick={() => onSelectFinding && onSelectFinding(event.finding_id)}
                      className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/25 text-[10px] font-mono flex items-center gap-1 transition-colors"
                      title="View Finding"
                    >
                      <FileCheck className="w-3 h-3" />
                      Finding
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
