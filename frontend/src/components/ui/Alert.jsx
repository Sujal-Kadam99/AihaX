import { AlertCircle, CheckCircle2, Info, AlertTriangle } from 'lucide-react';
import { cn } from '../../lib/utils';

const VARIANTS = {
  info: {
    bg: 'bg-info-bg border-info/30 text-info',
    icon: Info,
  },
  success: {
    bg: 'bg-low-bg border-low/30 text-low',
    icon: CheckCircle2,
  },
  warning: {
    bg: 'bg-medium-bg border-medium/30 text-medium',
    icon: AlertTriangle,
  },
  destructive: {
    bg: 'bg-critical-bg border-critical/30 text-critical',
    icon: AlertCircle,
  },
};

export default function Alert({
  title,
  children,
  variant = 'info',
  className = '',
  icon: CustomIcon,
  ...props
}) {
  const style = VARIANTS[variant] || VARIANTS.info;
  const IconComponent = CustomIcon || style.icon;

  return (
    <div
      role="alert"
      className={cn('flex items-start p-4 rounded border text-sm gap-3', style.bg, className)}
      {...props}
    >
      <IconComponent className="w-5 h-5 shrink-0 mt-0.5" aria-hidden="true" />
      <div className="flex-1">
        {title && <h5 className="font-semibold mb-0.5">{title}</h5>}
        {children && <div className="text-xs opacity-90">{children}</div>}
      </div>
    </div>
  );
}
