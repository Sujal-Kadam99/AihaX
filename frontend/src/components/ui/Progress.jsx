import { cn } from '../../lib/utils';

export function Progress({
  value = 0,
  max = 100,
  className = '',
  barClassName = '',
  showValue = false,
  color = 'accent',
}) {
  const percentage = Math.min(Math.max(0, (value / max) * 100), 100);

  const COLOR_CLASSES = {
    accent: 'bg-accent',
    green: 'bg-low',
    amber: 'bg-medium',
    red: 'bg-critical',
  };

  return (
    <div className="w-full space-y-1">
      <div className={cn('w-full bg-surface-2 rounded h-2 overflow-hidden', className)}>
        <div
          role="progressbar"
          aria-valuenow={Math.round(percentage)}
          aria-valuemin={0}
          aria-valuemax={100}
          className={cn(
            'h-full rounded transition-all duration-500 ease-out',
            COLOR_CLASSES[color] || COLOR_CLASSES.accent,
            barClassName
          )}
          style={{ width: `${percentage}%` }}
        />
      </div>
      {showValue && (
        <p className="text-xs text-text-secondary text-right font-display">{Math.round(percentage)}%</p>
      )}
    </div>
  );
}

export default Progress;
