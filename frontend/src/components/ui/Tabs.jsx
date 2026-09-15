import { cn } from '../../lib/utils';

export function Tabs({ tabs = [], activeTab, onChange, className = '' }) {
  return (
    <div
      role="tablist"
      aria-label="Content Tabs"
      className={cn('flex border-b border-border', className)}
    >
      {tabs.map((tab) => {
        const key = typeof tab === 'string' ? tab : tab.id;
        const label = typeof tab === 'string' ? tab : tab.label;
        const isActive = activeTab === key;

        return (
          <button
            key={key}
            role="tab"
            aria-selected={isActive}
            tabIndex={isActive ? 0 : -1}
            onClick={() => onChange?.(key)}
            className={cn(
              'flex-1 py-2.5 px-3 text-xs font-medium transition-colors cursor-pointer text-center relative focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
              isActive
                ? 'text-accent font-semibold border-b-2 border-accent'
                : 'text-text-secondary hover:text-text-primary'
            )}
          >
            {label}
          </button>
        );
      })}
    </div>
  );
}

export default Tabs;
