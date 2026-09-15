import { AlertCircle, CheckCircle2, Info, AlertTriangle, X } from 'lucide-react';
import { useToast } from '../../hooks/useToast';
import { cn } from '../../lib/utils';

const ICONS = {
  info: Info,
  success: CheckCircle2,
  warning: AlertTriangle,
  error: AlertCircle,
};

const STYLES = {
  info: 'bg-surface border-info/40 text-text-primary',
  success: 'bg-surface border-low/40 text-text-primary',
  warning: 'bg-surface border-medium/40 text-text-primary',
  error: 'bg-surface border-critical/40 text-text-primary',
};

const ICON_COLORS = {
  info: 'text-info',
  success: 'text-low',
  warning: 'text-medium',
  error: 'text-critical',
};

export default function ToastContainer() {
  const { toasts, removeToast } = useToast();

  if (toasts.length === 0) return null;

  return (
    <div
      aria-live="polite"
      aria-atomic="false"
      className="fixed bottom-4 right-4 z-50 flex flex-col space-y-2 max-w-sm w-full pointer-events-none"
    >
      {toasts.map((toast) => {
        const IconComponent = ICONS[toast.variant] || ICONS.info;
        const iconColor = ICON_COLORS[toast.variant] || ICON_COLORS.info;

        return (
          <div
            key={toast.id}
            role="status"
            className={cn(
              'pointer-events-auto flex items-start p-4 rounded-lg border shadow-lg transition-all animate-fade-in gap-3',
              STYLES[toast.variant] || STYLES.info
            )}
          >
            <IconComponent className={cn('w-5 h-5 shrink-0 mt-0.5', iconColor)} aria-hidden="true" />
            <div className="flex-1 text-sm">
              {toast.title && <h4 className="font-semibold text-text-primary">{toast.title}</h4>}
              {toast.message && <p className="text-text-secondary text-xs mt-0.5">{toast.message}</p>}
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              className="text-text-muted hover:text-text-primary p-0.5 rounded transition-colors"
              aria-label="Dismiss notification"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
