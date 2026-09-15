import { useState, useEffect } from 'react';
import { Link2, ShieldCheck, AlertOctagon, RefreshCw, ArrowDown } from 'lucide-react';
import { getValidationPlanEvidenceChain } from '../lib/api';


export default function EvidenceChainViewer({ campaignId, planId }) {
  const [chainData, setChainData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verificationStatus, setVerificationStatus] = useState('VERIFIED');

  useEffect(() => {
    if (campaignId && planId) {
      fetchChain();
    }
  }, [campaignId, planId]);

  const fetchChain = async () => {
    setLoading(true);
    try {
      const res = await getValidationPlanEvidenceChain(campaignId, planId);
      if (res?.data?.data) {
        setChainData(res.data.data.chain);
        setVerificationStatus(res.data.data.is_valid ? 'VERIFIED' : 'TAMPER DETECTED');
      }
    } catch (err) {
      console.error('Failed to fetch evidence chain:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    await new Promise((r) => setTimeout(r, 600));
    await fetchChain();
    setVerifying(false);
  };

  const nodes = chainData?.nodes || [];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-100 shadow-xl space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-cyan-500/10 rounded-lg text-cyan-400 border border-cyan-500/20">
            <Link2 className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white">Cryptographic Evidence Chain</h2>
            <p className="text-xs text-slate-400">Unbroken SHA-256 evidence chain verification</p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <span
            className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold border ${
              verificationStatus === 'VERIFIED'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-red-500/10 text-red-400 border-red-500/30'
            }`}
          >
            {verificationStatus === 'VERIFIED' ? (
              <ShieldCheck className="w-3.5 h-3.5 mr-1 text-emerald-400" />
            ) : (
              <AlertOctagon className="w-3.5 h-3.5 mr-1 text-red-400" />
            )}
            {verificationStatus}
          </span>

          <button
            onClick={handleVerify}
            disabled={verifying}
            className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition border border-slate-700 flex items-center space-x-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            <span>Verify Chain Integrity</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="py-12 text-center text-slate-500">Loading evidence chain...</div>
      ) : nodes.length === 0 ? (
        <div className="py-12 text-center text-slate-500">No evidence chain generated yet for this plan.</div>
      ) : (
        <div className="space-y-3">
          {nodes.map((node, index) => (
            <div key={node.node_id || index} className="relative">
              <div className="bg-slate-800/40 border border-slate-800 hover:border-slate-700 rounded-lg p-4 transition space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 text-xs font-bold flex items-center justify-center">
                      {index + 1}
                    </span>
                    <span className="font-bold text-xs text-white uppercase tracking-wider">{node.node_type}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono">Timestamp: {node.timestamp?.slice(11, 19)}</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono pt-1">
                  <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                    <div className="text-slate-500 text-[10px]">Previous Hash:</div>
                    <div className="text-slate-400 truncate">{node.previous_hash}</div>
                  </div>
                  <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                    <div className="text-slate-500 text-[10px]">Node Hash:</div>
                    <div className="text-cyan-400 truncate font-semibold">{node.node_hash}</div>
                  </div>
                </div>
              </div>

              {index < nodes.length - 1 && (
                <div className="flex justify-center my-1 text-slate-600">
                  <ArrowDown className="w-4 h-4" />
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
