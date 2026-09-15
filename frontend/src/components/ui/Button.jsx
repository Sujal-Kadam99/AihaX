import { forwardRef } from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';

const VARIANTS = {
  primary: 'bg-accent text-background hover:bg-accent-hover font-semibold shadow-sm',
  secondary: 'bg-surface-2 text-text-primary hover:bg-surface-hover border border-border',
  outline: 'bg-transparent text-text-primary hover:bg-surface-hover border border-border',
  ghost: 'bg-transparent text-text-secondary hover:text-text-primary hover:bg-surface-hover',
  danger: 'bg-critical text-white hover:opacity-90 font-semibold shadow-sm',
  accent: 'bg-accent/20 text-accent border border-accent/40 hover:bg-accent/30 font-medium',
};

const SIZES = {
  xs: 'h-7 px-2 text-xs gap-1',
  sm: 'h-8 px-3 text-xs gap-1.5',
  md: 'h-10 px-4 text-sm gap-2',
  lg: 'h-12 px-6 text-base gap-2.5',
};

const Button = forwardRef(function Button(
  {
    children,
    className = '',
    variant = 'primary',
    size = 'md',
    isLoading = false,
    loading = false,
    disabled = false,
    startIcon: StartIcon,
    endIcon: EndIcon,
    type = 'button',
    ...props
  },
  ref
) {
  const isButtonDisabled = disabled || isLoading || loading;
  const isCurrentlyLoading = isLoading || loading;

  return (
    <button
      ref={ref}
      type={type}
      disabled={isButtonDisabled}
      className={cn(
        'inline-flex items-center justify-center rounded font-medium transition-colors cursor-pointer',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background',
        'disabled:opacity-50 disabled:cursor-not-allowed disabled:pointer-events-none',
        VARIANTS[variant] || VARIANTS.primary,
        SIZES[size] || SIZES.md,
        className
      )}
      {...props}
    >
      {isCurrentlyLoading ? (
        <Loader2 className="w-4 h-4 animate-spin text-current" role="status" aria-label="Loading" />
      ) : StartIcon ? (
        <StartIcon className="w-4 h-4 shrink-0" aria-hidden="true" />
      ) : null}
      <span>{children}</span>
      {!isCurrentlyLoading && EndIcon && <EndIcon className="w-4 h-4 shrink-0" aria-hidden="true" />}
    </button>
  );
});

export default Button;
