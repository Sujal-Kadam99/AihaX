import { useState, useEffect, useRef } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Target,
  ShieldAlert,
  Search,
  FileText,
  Database,
  History,
  Settings as SettingsIcon,
  ShieldCheck,
  Sun,
  Moon,
  User as UserIcon,
  Users,
} from 'lucide-react';
import { useTheme } from '../hooks/useTheme';
import { useAuth } from '../hooks/useAuth';
import { healthCheck } from '../lib/api';
import { cn } from '../lib/utils';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/targets', icon: Target, label: 'Targets' },
  { to: '/campaigns', icon: ShieldAlert, label: 'Campaigns' },
  { to: '/findings', icon: Search, label: 'Findings' },
  { to: '/reports', icon: FileText, label: 'Reports' },
  { to: '/evidence', icon: Database, label: 'Evidence' },
  { to: '/audit', icon: History, label: 'Audit' },
  { to: '/workspaces', icon: Users, label: 'Workspaces' },
];

export default function Layout() {
  const { resolvedTheme, toggleTheme } = useTheme();
  const { user } = useAuth();
  const location = useLocation();
  const [systemStatus, setSystemStatus] = useState({ state: 'ready', label: 'System Ready' });
  const inFlightRef = useRef(false);
  const backoffRef = useRef(20000);

  useEffect(() => {
    let isMounted = true;
    let timerId = null;

    const performHealthCheck = async () => {
      // Avoid duplicate concurrent health check calls
      if (inFlightRef.current) return;
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        // Delay check when page is hidden
        scheduleNext(30000);
        return;
      }

      inFlightRef.current = true;
      try {
        const res = await healthCheck();
        if (isMounted) {
          backoffRef.current = 20000; // Reset backoff on success
          if (res.data?.status === 'ok') {
            if (res.data?.redis === 'error') {
              setSystemStatus({ state: 'warning', label: 'Ready (Redis Optional)' });
            } else {
              setSystemStatus({ state: 'ready', label: 'System Ready' });
            }
          } else {
            setSystemStatus({ state: 'warning', label: 'Degraded' });
          }
        }
      } catch (err) {
        if (isMounted) {
          setSystemStatus({ state: 'error', label: 'Backend Disconnected' });
          // Exponential backoff up to 60s
          backoffRef.current = Math.min(60000, backoffRef.current * 1.5);
        }
      } finally {
        inFlightRef.current = false;
        if (isMounted) {
          scheduleNext(backoffRef.current);
        }
      }
    };

    const scheduleNext = (delay) => {
      if (timerId) clearTimeout(timerId);
      timerId = setTimeout(performHealthCheck, delay);
    };

    // Initial check
    performHealthCheck();

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        performHealthCheck();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      isMounted = false;
      if (timerId) clearTimeout(timerId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  return (
    <div className="flex h-screen bg-background text-text-primary overflow-hidden font-sans">
      {/* Compact Desktop Left Sidebar */}
      <aside className="w-56 bg-surface border-r border-border flex flex-col justify-between flex-shrink-0 select-none">
        <div>
          {/* Header Brand */}
          <div className="h-14 px-4 flex items-center gap-2.5 border-b border-border">
            <div className="w-8 h-8 rounded bg-accent/15 flex items-center justify-center text-accent">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold tracking-tight text-text-primary">AihaX Console</div>
              <div className="text-[10px] text-text-muted font-mono uppercase tracking-wider">Security Ops</div>
            </div>
          </div>

          {/* Nav Items */}
          <nav className="p-2 space-y-0.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.to;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={cn(
                    'flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-colors',
                    isActive
                      ? 'bg-accent/10 text-accent font-semibold'
                      : 'text-text-secondary hover:text-text-primary hover:bg-surface-2'
                  )}
                >
                  <Icon className="w-4 h-4 flex-shrink-0" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* Bottom Settings & Version */}
        <div className="p-2 border-t border-border space-y-1">
          <NavLink
            to="/settings"
            className={cn(
              'flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-colors',
              location.pathname === '/settings'
                ? 'bg-accent/10 text-accent font-semibold'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-2'
            )}
          >
            <SettingsIcon className="w-4 h-4 flex-shrink-0" />
            <span>Settings</span>
          </NavLink>
          <div className="px-3 py-1.5 flex items-center justify-between text-[10px] text-text-muted font-mono">
            <span>v1.0.0-phase8</span>
            <span>WAL Mode</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Minimal Top Bar */}
        <header className="h-14 bg-surface border-b border-border px-6 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-3">
            <span className="text-xs font-medium text-text-secondary font-mono">AihaX</span>
            <span className="text-text-muted">/</span>
            <span className="text-xs font-semibold text-text-primary capitalize">
              {location.pathname === '/' ? 'Dashboard' : location.pathname.replace('/', '')}
            </span>
          </div>

          <div className="flex items-center gap-4">
            {/* Real-time System Status Indicator */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-surface-2 border border-border text-[11px] font-mono">
              <span
                className={cn(
                  'w-2 h-2 rounded-full',
                  systemStatus.state === 'ready'
                    ? 'bg-emerald-400 animate-pulse'
                    : systemStatus.state === 'warning'
                    ? 'bg-amber-400'
                    : 'bg-red-400'
                )}
              />
              <span className="text-text-secondary">{systemStatus.label}</span>
            </div>

            {/* Operator Identifier Badge */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-surface-2 border border-border text-xs text-text-primary">
              <UserIcon className="w-3.5 h-3.5 text-accent" />
              <span className="font-mono text-[11px]">
                Operator: <strong className="text-text-primary">{user?.role || 'Admin'}</strong>
              </span>
              <span className="ml-1 text-[10px] px-1 rounded bg-emerald-500/10 text-emerald-400 font-mono">
                AUTHD
              </span>
            </div>

            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              className="p-1.5 rounded-md hover:bg-surface-2 text-text-secondary hover:text-text-primary transition-colors"
              title="Toggle Theme"
            >
              {resolvedTheme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
        </header>

        {/* Dynamic Route Body */}
        <main className="flex-1 overflow-y-auto p-6 bg-background">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
