import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { getScan, cancelScan } from '../lib/api';
import { createScanSocket } from '../lib/socket';
import AgentCard from '../components/AgentCard';
import LiveFeed from '../components/LiveFeed';
import LiveTerminal from '../components/LiveTerminal';
import ScanTimer from '../components/ScanTimer';
import SeverityBadge from '../components/SeverityBadge';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Skeleton from '../components/ui/Skeleton';
import { Terminal } from 'lucide-react';

const AGENT_NAMES = {
  1: 'Recon Agent',
  2: 'Authentication Agent',
  3: 'Vulnerability Testing Agent',
  4: 'Verification Agent',
  5: 'Learning Agent',
  6: 'Exploit Chain Agent',
  7: 'Remediation Agent',
  8: 'Business Impact Agent',
  9: 'Report Generation Agent',
};

export default function LiveScan() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [agents, setAgents] = useState({});
  const [findings, setFindings] = useState([]);
  const [counts, setCounts] = useState({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  const [showCancelConfirm, setShowCancelConfirm] = useState(false);
  const [showTerminal, setShowTerminal] = useState(false);
  const [logs, setLogs] = useState([]);

  const pollScan = useCallback(async () => {
    try {
      const res = await getScan(scanId);
      setScan(res.data);
      const agentMap = {};
      res.data.agents.forEach((a) => {
        agentMap[a.agent_id] = a;
      });
      setAgents(agentMap);
      setCounts(res.data.findings_count);
      if (res.data.status === 'complete') {
        setTimeout(() => navigate(`/findings/${scanId}`), 5000);
      }
    } catch (err) {
      console.error('Poll error:', err);
    }
  }, [scanId, navigate]);

  useEffect(() => {
    setTimeout(() => { pollScan(); }, 0);
    const interval = setInterval(pollScan, 5000);
    return () => clearInterval(interval);
  }, [pollScan]);

  useEffect(() => {
    let socket = null;
    createScanSocket(scanId, {
      onMessage: (data) => {
        // Update agent cards
        setAgents((prev) => ({
          ...prev,
          [data.agent_id]: {
            agent_id: data.agent_id,
            agent_name: data.agent_name,
            status: data.status,
            progress: data.progress,
            message: data.message,
          },
        }));

        // Append to live terminal logs
        setLogs((prev) => [
          ...prev,
          {
            ts: new Date().toISOString(),
            agent_id: data.agent_id,
            agent_name: data.agent_name,
            status: data.status,
            progress: data.progress,
            message: data.message,
            finding: data.finding || null,
          },
        ]);

        if (data.finding) {
          setFindings((prev) => [data.finding, ...prev]);
          setCounts((prev) => ({
            ...prev,
            [data.finding.severity]: (prev[data.finding.severity] || 0) + 1,
          }));
        }
      },
    }).then((s) => { socket = s; });
    return () => socket?.close();
  }, [scanId]);

  const handleCancel = async () => {
    await cancelScan(scanId);
    setShowCancelConfirm(false);
    navigate('/');
  };

  if (!scan) {
    return (
      <div className="p-6 space-y-4 max-w-5xl mx-auto">
        <Skeleton className="h-10 w-1/3" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const now = Date.now();

  return (
    <div className="p-6 h-full flex flex-col space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-xl font-bold text-text-primary">{scan.target_url}</h1>
          <p className="text-xs text-text-muted font-code mt-1">Scan ID: {scanId}</p>
        </div>
        <div className="flex items-center gap-4">
          <ScanTimer startTime={scan.created_at || now} />
          <StatusPill status={scan.status} />
        </div>
      </div>

      {/* Main grid */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-3 gap-6 min-h-0">
        {/* Agent cards + terminal toggle */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-xs text-text-secondary uppercase tracking-wide font-semibold">
              Agent Pipeline
            </h2>
            <button
              onClick={() => setShowTerminal((v) => !v)}
              className={`flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border transition-all ${
                showTerminal
                  ? 'border-cyan-500/60 bg-cyan-500/10 text-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.15)]'
                  : 'border-border-subtle text-text-secondary hover:border-cyan-500/40 hover:text-cyan-400 hover:bg-cyan-500/5'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              {showTerminal ? 'Hide Live Logs' : 'View Live Logs'}
            </button>
          </div>

          <div className="grid grid-cols-3 gap-3">
            {Array.from({ length: 9 }, (_, i) => i + 1).map((id) => {
              const agent = agents[id] || {};
              return (
                <AgentCard
                  key={id}
                  agentId={id}
                  agentName={agent.agent_name || AGENT_NAMES[id]}
                  status={agent.status || 'pending'}
                  progress={agent.progress || 0}
                  message={agent.message || ''}
                />
              );
            })}
          </div>

          {/* Live Terminal — toggleable */}
          {showTerminal && (
            <div className="mt-3 rounded-lg overflow-hidden border border-[#30363d] shadow-[0_0_24px_rgba(34,211,238,0.08)] animate-[fadeIn_0.2s_ease]">
              <LiveTerminal logs={logs} />
            </div>
          )}
        </div>

        {/* Live Findings feed */}
        <div className="flex flex-col min-h-0 space-y-3">
          <h2 className="font-display text-xs text-text-secondary uppercase tracking-wide font-semibold">
            Live Findings
          </h2>
          <div className="flex-1 bg-surface border border-border rounded-lg p-3 min-h-[300px] overflow-hidden">
            <LiveFeed findings={findings} />
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between pt-4 border-t border-border">
        <div className="flex gap-2">
          {Object.entries(counts).map(([sev, count]) =>
            count > 0 ? <SeverityBadge key={sev} severity={sev} /> : null
          )}
        </div>
        <div className="flex gap-3">
          {scan.status === 'complete' && (
            <Link to={`/findings/${scanId}`}>
              <Button variant="primary">View Results</Button>
            </Link>
          )}
          {scan.status === 'running' && (
            <Button variant="danger" onClick={() => setShowCancelConfirm(true)}>
              Cancel Scan
            </Button>
          )}
        </div>
      </div>

      {/* Cancel confirm modal */}
      <Modal
        isOpen={showCancelConfirm}
        onClose={() => setShowCancelConfirm(false)}
        title="Cancel Scan?"
        description="This will stop all running execution agents immediately. This action cannot be undone."
      >
        <div className="flex justify-end gap-3 pt-4">
          <Button variant="ghost" onClick={() => setShowCancelConfirm(false)}>
            Keep Running
          </Button>
          <Button variant="danger" onClick={handleCancel}>
            Cancel Scan
          </Button>
        </div>
      </Modal>

      {/* Scan complete toast */}
      {scan.status === 'complete' && (
        <div className="fixed bottom-6 right-6 bg-surface border border-low rounded-lg p-4 shadow-xl z-40">
          <p className="text-sm text-low font-medium">
            Scan complete! Redirecting to findings report in 5s...
          </p>
        </div>
      )}
    </div>
  );
}

function StatusPill({ status }) {
  const variants = {
    running: 'info',
    complete: 'success',
    error: 'destructive',
    pending: 'secondary',
  };
  return <Badge variant={variants[status] || 'secondary'}>{status}</Badge>;
}
