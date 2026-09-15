import { forwardRef, useId } from 'react';
import { cn } from '../../lib/utils';

const Input = forwardRef(function Input(
  {
    label,
    error,
    helperText,
    startIcon: StartIcon,
    endIcon: EndIcon,
    className = '',
    id: customId,
    type = 'text',
    disabled = false,
    ...props
  },
  ref
) {
  const generatedId = useId();
  const inputId = customId || generatedId;
  const errorId = `${inputId}-error`;
  const helperId = `${inputId}-helper`;

  return (
    <div className="w-full space-y-1.5">
      {label && (
        <label htmlFor={inputId} className="block text-xs font-medium text-text-secondary">
          {label}
        </label>
      )}
      <div className="relative flex items-center">
        {StartIcon && (
          <div className="absolute left-3 text-text-muted pointer-events-none">
            <StartIcon className="w-4 h-4" aria-hidden="true" />
          </div>
        )}
        <input
          ref={ref}
          id={inputId}
          type={type}
          disabled={disabled}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? errorId : helperText ? helperId : undefined}
          className={cn(
            'w-full bg-surface-2 border border-border rounded text-text-primary text-sm px-3 py-2 transition-colors',
            'placeholder:text-text-muted',
            'focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent',
            'disabled:opacity-50 disabled:cursor-not-allowed',
            error && 'border-critical focus:ring-critical',
            StartIcon && 'pl-9',
            EndIcon && 'pr-9',
            className
          )}
          {...props}
        />
        {EndIcon && (
          <div className="absolute right-3 text-text-muted pointer-events-none">
            <EndIcon className="w-4 h-4" aria-hidden="true" />
          </div>
        )}
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

export default Input;
