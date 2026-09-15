import { useState, useEffect } from 'react';
import { Network, Search, Filter, Hash } from 'lucide-react';
import { getAttackSurface } from '../lib/api';


export default function AttackSurfaceGraph({ campaignId, targetUrl }) {
  const [snapshot, setSnapshot] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetchSnapshot();
  }, [campaignId]);

  const fetchSnapshot = async () => {
    setLoading(true);
    try {
      const res = await getAttackSurface(campaignId);
      if (res?.data?.data) {
        setSnapshot(res.data.data);
      }
    } catch (err) {
      console.error('Failed to fetch attack surface snapshot:', err);
    } finally {
      setLoading(false);
    }
  };

  const nodes = snapshot?.nodes || [];
  const edges = snapshot?.edges || [];

  const filteredNodes = nodes.filter((n) => {
    const matchesFilter = filterType === 'ALL' || n.node_type === filterType;
    const matchesSearch =
      !searchQuery ||
      n.canonical_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (n.endpoint && n.endpoint.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (n.parameter && n.parameter.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-100 shadow-xl space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-cyan-500/10 rounded-lg text-cyan-400 border border-cyan-500/20">
            <Network className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white">Attack Surface Graph</h2>
            <p className="text-xs text-slate-400">
              Authorized passive inventory for <span className="text-cyan-400 font-mono">{targetUrl || snapshot?.target || 'Target'}</span>
            </p>
          </div>
        </div>

        {snapshot?.snapshot_hash && (
          <div className="flex items-center space-x-2 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700 font-mono text-xs text-slate-300">
            <Hash className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Snapshot:</span>
            <span>{snapshot.snapshot_hash.slice(0, 16)}...</span>
          </div>
        )}
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-slate-800/50 border border-slate-800 p-3.5 rounded-lg">
          <div className="text-xs text-slate-400 font-medium">Total Nodes</div>
          <div className="text-2xl font-bold text-white mt-1">{nodes.length}</div>
        </div>
        <div className="bg-slate-800/50 border border-slate-800 p-3.5 rounded-lg">
          <div className="text-xs text-slate-400 font-medium">Relationships</div>
          <div className="text-2xl font-bold text-cyan-400 mt-1">{edges.length}</div>
        </div>
        <div className="bg-slate-800/50 border border-slate-800 p-3.5 rounded-lg">
          <div className="text-xs text-slate-400 font-medium">Endpoints</div>
          <div className="text-2xl font-bold text-indigo-400 mt-1">
            {nodes.filter((n) => n.node_type === 'ENDPOINT' || n.node_type === 'API_ROUTE').length}
          </div>
        </div>
        <div className="bg-slate-800/50 border border-slate-800 p-3.5 rounded-lg">
          <div className="text-xs text-slate-400 font-medium">Parameters</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">
            {nodes.filter((n) => n.node_type === 'PARAMETER').length}
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
          <input
            type="text"
            placeholder="Search nodes, URLs, parameters..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 pl-9 pr-4 py-2 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="flex items-center space-x-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-slate-200 px-3 py-2 rounded-lg text-sm focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Types</option>
            <option value="TARGET">TARGET</option>
            <option value="ENDPOINT">ENDPOINT</option>
            <option value="PARAMETER">PARAMETER</option>
            <option value="API_ROUTE">API_ROUTE</option>
            <option value="REDIRECT">REDIRECT</option>
            <option value="HEADER">HEADER</option>
          </select>
        </div>
      </div>

      {/* Nodes Table */}
      <div className="overflow-x-auto border border-slate-800 rounded-lg">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-800/80 text-slate-400 uppercase font-semibold">
            <tr>
              <th className="py-3 px-4">Node Type</th>
              <th className="py-3 px-4">Canonical URL / Path</th>
              <th className="py-3 px-4">Method / Param</th>
              <th className="py-3 px-4">Source</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Hash</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
            {loading ? (
              <tr>
                <td colSpan="6" className="py-8 text-center text-slate-500">
                  Loading attack surface graph...
                </td>
              </tr>
            ) : filteredNodes.length === 0 ? (
              <tr>
                <td colSpan="6" className="py-8 text-center text-slate-500">
                  No attack surface nodes found matching criteria.
                </td>
              </tr>
            ) : (
              filteredNodes.map((node) => (
                <tr key={node.id} className="hover:bg-slate-800/40 transition">
                  <td className="py-3 px-4 font-medium">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border ${
                        node.node_type === 'TARGET'
                          ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                          : node.node_type === 'ENDPOINT'
                          ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30'
                          : node.node_type === 'PARAMETER'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          : node.node_type === 'REDIRECT'
                          ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                          : 'bg-slate-700/40 text-slate-300 border-slate-600'
                      }`}
                    >
                      {node.node_type}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-200 truncate max-w-xs">{node.canonical_url}</td>
                  <td className="py-3 px-4 font-mono text-slate-400">
                    {node.method && <span className="text-emerald-400 font-bold mr-1.5">{node.method}</span>}
                    {node.parameter && <span className="text-amber-300">param: {node.parameter}</span>}
                    {!node.method && !node.parameter && '-'}
                  </td>
                  <td className="py-3 px-4 text-slate-400">{node.source}</td>
                  <td className="py-3 px-4">
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-emerald-400 border border-emerald-500/30">
                      {node.status || 'OBSERVED'}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-500 text-[10px]">
                    {node.observation_hash?.slice(0, 10)}...
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
