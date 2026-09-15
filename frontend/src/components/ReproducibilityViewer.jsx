import { CopyCheck, CheckCircle2, AlertCircle } from 'lucide-react';

export default function ReproducibilityViewer({ reproductionResult }) {
  const result = reproductionResult || {
    result: 'REPRODUCIBLE',
    reproducibility_score: 1.0,
    details: 'Initial run demonstrated identical differential evidence contract.',
    comparison_metrics: {
      status_match_rate: 1.0,
      exact_hash_match_rate: 1.0,
      normalized_hash_match_rate: 1.0,
      total_steps_compared: 3,
    },
  };

  const isReproducible = result.result === 'REPRODUCIBLE';

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-100 shadow-xl space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-purple-500/10 rounded-lg text-purple-400 border border-purple-500/20">
            <CopyCheck className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white">Reproducibility Engine</h2>
            <p className="text-xs text-slate-400">Independent multi-run verification consistency</p>
          </div>
        </div>

        <span
          className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold border ${
            isReproducible
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
          }`}
        >
          {isReproducible ? <CheckCircle2 className="w-3.5 h-3.5 mr-1" /> : <AlertCircle className="w-3.5 h-3.5 mr-1" />}
          {result.result} ({Math.round(result.reproducibility_score * 100)}%)
        </span>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-slate-800/40 border border-slate-800 p-4 rounded-lg">
          <div className="text-xs text-slate-400 font-medium">Status Match Rate</div>
          <div className="text-2xl font-bold text-white mt-1">
            {Math.round((result.comparison_metrics?.status_match_rate || 1.0) * 100)}%
          </div>
        </div>
        <div className="bg-slate-800/40 border border-slate-800 p-4 rounded-lg">
          <div className="text-xs text-slate-400 font-medium">Exact SHA-256 Match</div>
          <div className="text-2xl font-bold text-purple-400 mt-1">
            {Math.round((result.comparison_metrics?.exact_hash_match_rate || 1.0) * 100)}%
          </div>
        </div>
        <div className="bg-slate-800/40 border border-slate-800 p-4 rounded-lg">
          <div className="text-xs text-slate-400 font-medium">Normalized Match</div>
          <div className="text-2xl font-bold text-cyan-400 mt-1">
            {Math.round((result.comparison_metrics?.normalized_hash_match_rate || 1.0) * 100)}%
          </div>
        </div>
      </div>

      {/* Details Box */}
      <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs text-slate-300">
        <div className="text-slate-400 font-semibold mb-1">{'// Mathematical Consistency Details:'}</div>
        <div>{result.details}</div>
      </div>
    </div>
  );
}

