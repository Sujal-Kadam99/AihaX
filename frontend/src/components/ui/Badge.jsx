import { cn } from '../../lib/utils';

const VARIANTS = {
  default: 'bg-surface-2 text-text-primary border-border',
  secondary: 'bg-surface-hover text-text-secondary border-transparent',
  outline: 'bg-transparent text-text-secondary border-border',
  destructive: 'bg-critical-bg text-critical border-critical/30',
  success: 'bg-low-bg text-low border-low/30',
  warning: 'bg-medium-bg text-medium border-medium/30',
  info: 'bg-info-bg text-info border-info/30',
};

const SIZES = {
  sm: 'px-1.5 py-0.5 text-[10px]',
  md: 'px-2.5 py-0.5 text-xs',
};

export default function Badge({
  children,
  className = '',
  variant = 'default',
  size = 'md',
  ...props
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center font-medium uppercase border rounded tracking-wide',
        VARIANTS[variant] || VARIANTS.default,
        SIZES[size] || SIZES.md,
        className
      )}
      {...props}
    >
      {children}
    </span>
  );
}
