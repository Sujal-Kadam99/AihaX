import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { cn } from '../../lib/utils';

export default function Drawer({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  className = '',
  width = 'w-[450px]',
}) {
  const drawerRef = useRef(null);

  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose?.();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    document.body.style.overflow = 'hidden';

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const drawerContent = (
    <div className="fixed inset-0 z-50 overflow-hidden">
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        ref={drawerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? 'drawer-title' : undefined}
        className={cn(
          'fixed right-0 top-0 h-full bg-surface border-l border-border shadow-2xl flex flex-col z-10 transition-transform duration-300',
          width,
          className
        )}
      >
        <div className="flex items-center justify-between p-4 border-b border-border">
          <div>
            {title && (
              <h2 id="drawer-title" className="font-display text-lg font-semibold text-text-primary">
                {title}
              </h2>
            )}
            {subtitle && <p className="text-xs text-text-secondary mt-0.5">{subtitle}</p>}
          </div>
          <button
            onClick={onClose}
            aria-label="Close panel"
            className="text-text-secondary hover:text-text-primary p-1 rounded hover:bg-surface-2 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4">{children}</div>
      </div>
    </div>
  );

  const target = document.getElementById('modal-root') || document.body;
  return createPortal(drawerContent, target);
}
