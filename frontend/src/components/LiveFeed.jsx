import SeverityBadge from './SeverityBadge';
import EmptyState from './ui/EmptyState';
import { cn } from '../lib/utils';

const SEVERITY_BORDER = {
  critical: 'border-l-critical',
  high: 'border-l-high',
  medium: 'border-l-medium',
  low: 'border-l-low',
  info: 'border-l-info',
};

export default function LiveFeed({ findings = [], onSelect }) {
  if (findings.length === 0) {
    return (
      <EmptyState
        title="Live Stream Active"
        description="No vulnerabilities detected yet. Automated checks in progress..."
      />
    );
  }

  return (
    <div
      aria-live="polite"
      aria-atomic="false"
      className="space-y-2 overflow-y-auto h-full pr-1"
    >
      {findings.map((finding, i) => (
        <div
          key={finding.id || i}
          onClick={() => onSelect?.(finding)}
          className={cn(
            'bg-surface border border-border border-l-4 rounded p-3 cursor-pointer hover:bg-surface-hover transition-colors',
            SEVERITY_BORDER[finding.severity] || SEVERITY_BORDER.info
          )}
        >
          <div className="flex items-center gap-2 mb-1">
            <SeverityBadge severity={finding.severity} />
            <span className="text-sm font-medium text-text-primary truncate">{finding.title}</span>
          </div>
          <p className="text-xs text-text-secondary truncate">
            {finding.url || finding.affected_url}
          </p>
          {finding.confidence && (
            <p className="text-xs text-text-muted mt-1 font-display">{finding.confidence}% confidence</p>
          )}
        </div>
      ))}
    </div>
  );
}
