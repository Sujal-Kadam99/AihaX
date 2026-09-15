import { ShieldAlert } from 'lucide-react';
import { cn } from '../../lib/utils';
import Button from './Button';

export default function EmptyState({
  title = 'No Data Found',
  description = 'There are no records to display at this time.',
  icon: Icon = ShieldAlert,
  actionLabel,
  onAction,
  className = '',
}) {
  return (
    <div className={cn('flex flex-col items-center justify-center p-8 text-center rounded border border-dashed border-border bg-surface/50', className)}>
      <div className="p-3 bg-surface-2 rounded-full mb-3 text-text-muted">
        <Icon className="w-8 h-8" aria-hidden="true" />
      </div>
      <h3 className="font-display text-base font-semibold text-text-primary mb-1">{title}</h3>
      <p className="text-xs text-text-secondary max-w-sm mb-4">{description}</p>
      {actionLabel && onAction && (
        <Button size="sm" onClick={onAction}>
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
