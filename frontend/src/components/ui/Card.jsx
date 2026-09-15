import { cn } from '../../lib/utils';

export function Card({ className = '', variant = 'default', children, ...props }) {
  return (
    <div
      className={cn(
        'bg-surface border border-border rounded-lg p-6 transition-all',
        variant === 'interactive' && 'hover:bg-surface-hover hover:border-border-strong cursor-pointer',
        variant === 'glow' && 'border-accent/40 shadow-glow',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({ className = '', children, ...props }) {
  return (
    <div className={cn('flex flex-col space-y-1.5 mb-4', className)} {...props}>
      {children}
    </div>
  );
}

export function CardTitle({ className = '', children, ...props }) {
  return (
    <h3 className={cn('font-display text-lg font-semibold text-text-primary', className)} {...props}>
      {children}
    </h3>
  );
}

export function CardDescription({ className = '', children, ...props }) {
  return (
    <p className={cn('text-xs text-text-secondary', className)} {...props}>
      {children}
    </p>
  );
}

export function CardContent({ className = '', children, ...props }) {
  return <div className={cn('', className)} {...props}>{children}</div>;
}

export function CardFooter({ className = '', children, ...props }) {
  return (
    <div className={cn('flex items-center justify-between mt-4 pt-4 border-t border-border-subtle', className)} {...props}>
      {children}
    </div>
  );
}

export default Card;
