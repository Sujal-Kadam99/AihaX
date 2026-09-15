import { forwardRef, useId } from 'react';
import { ChevronDown } from 'lucide-react';
import { cn } from '../../lib/utils';

const Select = forwardRef(function Select(
  {
    label,
    error,
    helperText,
    children,
    className = '',
    id: customId,
    disabled = false,
    ...props
  },
  ref
) {
  const generatedId = useId();
  const selectId = customId || generatedId;
  const errorId = `${selectId}-error`;
  const helperId = `${selectId}-helper`;

  return (
    <div className="w-full space-y-1.5">
      {label && (
        <label htmlFor={selectId} className="block text-xs font-medium text-text-secondary">
          {label}
        </label>
      )}
      <div className="relative flex items-center">
        <select
          ref={ref}
          id={selectId}
          disabled={disabled}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? errorId : helperText ? helperId : undefined}
          className={cn(
            'w-full bg-surface-2 border border-border rounded text-text-primary text-sm px-3 py-2 pr-9 transition-colors appearance-none cursor-pointer',
            'focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent',
            'disabled:opacity-50 disabled:cursor-not-allowed',
            error && 'border-critical focus:ring-critical',
            className
          )}
          {...props}
        >
          {children}
        </select>
        <ChevronDown
          className="w-4 h-4 text-text-muted absolute right-3 pointer-events-none"
          aria-hidden="true"
        />
      </div>
      {error ? (
        <p id={errorId} className="text-xs text-critical font-medium" role="alert">
          {error}
        </p>
      ) : helperText ? (
        <p id={helperId} className="text-xs text-text-muted">
          {helperText}
        </p>
      ) : null}
    </div>
  );
});

export default Select;
