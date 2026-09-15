import { Card, CardContent } from './ui/Card';
import Progress from './ui/Progress';
import Badge from './ui/Badge';

const STATUS_BADGE_VARIANTS = {
  pending: 'secondary',
  running: 'info',
  complete: 'success',
  error: 'destructive',
};

const STATUS_PROGRESS_COLORS = {
  pending: 'accent',
  running: 'accent',
  complete: 'green',
  error: 'red',
};

export default function AgentCard({
  agentId,
  agentName,
  status = 'pending',
  progress = 0,
  message = '',
}) {
  const badgeVariant = STATUS_BADGE_VARIANTS[status] || STATUS_BADGE_VARIANTS.pending;
  const progressColor = STATUS_PROGRESS_COLORS[status] || STATUS_PROGRESS_COLORS.pending;

  return (
    <Card variant={status === 'running' ? 'glow' : 'default'} className="transition-all">
      <CardContent className="space-y-2 p-0">
        <div className="flex items-center justify-between">
          <span className="font-display text-2xl font-bold text-text-muted">{agentId}</span>
          <Badge variant={badgeVariant}>{status}</Badge>
        </div>
        <h3 className="font-display text-sm font-medium text-text-primary">{agentName}</h3>
        <Progress value={progress} color={progressColor} />
        <p className="text-xs text-text-secondary truncate">{message || 'Waiting...'}</p>
      </CardContent>
    </Card>
  );
}
