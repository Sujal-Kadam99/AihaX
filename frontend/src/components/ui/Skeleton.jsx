import { cn } from '../../lib/utils';

export default function Skeleton({ className = '', ...props }) {
  return (
    <div
      aria-hidden="true"
      className={cn('bg-surface-2 rounded animate-pulse', className)}
      {...props}
    />
  );
}
