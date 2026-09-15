import Badge from './ui/Badge';

const SEVERITY_VARIANTS = {
  critical: 'destructive',
  high: 'warning',
  medium: 'warning',
  low: 'success',
  info: 'info',
};

export default function SeverityBadge({ severity, className = '' }) {
  const normalizedSeverity = (severity || 'info').toLowerCase();
  const variant = SEVERITY_VARIANTS[normalizedSeverity] || 'info';

  return (
    <Badge variant={variant} className={className}>
      {severity || 'info'}
    </Badge>
  );
}
