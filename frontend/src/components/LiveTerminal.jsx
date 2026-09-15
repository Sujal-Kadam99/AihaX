import { useEffect, useRef, useState } from 'react';

const AGENT_COLORS = {
  1: '#22d3ee',   // cyan - Recon
  2: '#a78bfa',   // violet - Auth
  3: '#f97316',   // orange - Vuln
  4: '#4ade80',   // green - Verify
  5: '#facc15',   // yellow - Learning
  6: '#fb7185',   // red - Exploit Chain
  7: '#60a5fa',   // blue - Remediation
  8: '#c084fc',   // purple - Impact
  9: '#34d399',   // emerald - Report
};

const AGENT_PREFIXES = {
  1: 'RECON',
  2: 'AUTH',
  3: 'VULN',
  4: 'VERIFY',
  5: 'LEARN',
  6: 'CHAIN',
  7: 'REMEDY',
  8: 'IMPACT',
  9: 'REPORT',
};

export default function LiveTerminal({ logs }) {
  const bottomRef = useRef(null);
  const containerRef = useRef(null);
  const [follow, setFollow] = useState(true);

  // Auto-scroll only when "follow" is on
  useEffect(() => {
    if (follow && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, follow]);

  // Detect manual scroll up → pause follow
  const handleScroll = () => {
    const el = containerRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop <= el.clientHeight + 40;
    setFollow(atBottom);
  };

  return (
    <div className="relative flex flex-col h-full">
      {/* Terminal header bar */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#0d1117] border-b border-[#30363d] rounded-t-lg">
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-[#f87171]" />
          <span className="w-3 h-3 rounded-full bg-[#facc15]" />
          <span className="w-3 h-3 rounded-full bg-[#4ade80]" />
          <span className="ml-3 text-xs font-mono text-[#7d8590]">aihax — live agent output</span>
        </div>
        <button
          onClick={() => {
            setFollow(true);
            bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
          }}
          className={`text-xs font-mono px-2 py-0.5 rounded border transition-colors ${
            follow
              ? 'border-[#22d3ee]/40 text-[#22d3ee] bg-[#22d3ee]/10'
              : 'border-[#30363d] text-[#7d8590] hover:border-[#22d3ee]/40 hover:text-[#22d3ee]'
          }`}
        >
          {follow ? '↓ following' : '↓ jump to bottom'}
        </button>
      </div>

      {/* Terminal body */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto bg-[#0d1117] rounded-b-lg p-4 font-mono text-xs leading-relaxed"
        style={{ minHeight: '320px', maxHeight: '420px' }}
      >
        {logs.length === 0 ? (
          <div className="flex items-center gap-2 text-[#7d8590]">
            <span className="animate-pulse text-[#22d3ee]">▶</span>
            <span>Waiting for agents to initialize...</span>
          </div>
        ) : (
          logs.map((log, i) => <TerminalLine key={i} log={log} />)
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

function TerminalLine({ log }) {
  const agentColor = AGENT_COLORS[log.agent_id] || '#7d8590';
  const agentPrefix = AGENT_PREFIXES[log.agent_id] || `AGT${log.agent_id}`;

  const ts = new Date(log.ts).toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  return (
    <div className="flex items-start gap-2 mb-0.5 hover:bg-white/[0.02] px-1 rounded group">
      {/* Timestamp */}
      <span className="text-[#7d8590] shrink-0 w-16">{ts}</span>

      {/* Agent badge */}
      <span
        className="shrink-0 font-bold w-14 text-right"
        style={{ color: agentColor }}
      >
        [{agentPrefix}]
      </span>

      {/* Status indicator */}
      {log.status === 'error' && (
        <span className="shrink-0 font-bold" style={{ color: '#f87171' }}>
          ✗
        </span>
      )}
      {log.status === 'complete' && (
        <span className="shrink-0 font-bold" style={{ color: '#4ade80' }}>
          ✓
        </span>
      )}
      {log.status === 'running' && (
        <span className="shrink-0 text-[#22c55e] animate-pulse">›</span>
      )}

      {/* Message */}
      <span
        className="break-all"
        style={{
          color: log.status === 'error' ? '#f87171' : log.status === 'complete' ? '#e6edf3' : '#c9d1d9',
        }}
      >
        {log.message}
        {log.finding && (
          <span
            className="ml-2 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase"
            style={{
              backgroundColor: severityBg(log.finding.severity),
              color: severityColor(log.finding.severity),
            }}
          >
            {log.finding.severity}: {log.finding.title}
          </span>
        )}
      </span>

      {/* Progress */}
      {log.progress > 0 && log.progress < 100 && (
        <span className="ml-auto shrink-0 text-[#7d8590]">{log.progress}%</span>
      )}
    </div>
  );
}

function severityBg(s) {
  return { critical: '#450a0a', high: '#431407', medium: '#422006', low: '#052e16', info: '#0c1a2e' }[s] || '#161b22';
}
function severityColor(s) {
  return { critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#4ade80', info: '#60a5fa' }[s] || '#7d8590';
}
