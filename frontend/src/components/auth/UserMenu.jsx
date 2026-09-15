import { useState } from 'react';
import { useAuth } from '../../hooks/useAuth';
import Button from '../ui/Button';
import LoginModal from './LoginModal';
import { LogOut } from 'lucide-react';

export default function UserMenu() {
  const { user, isAuthenticated, logout } = useAuth();
  const [isLoginOpen, setIsLoginOpen] = useState(false);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  if (!isAuthenticated || !user) {
    return (
      <>
        <Button variant="accent" size="sm" onClick={() => setIsLoginOpen(true)}>
          Sign In
        </Button>
        <LoginModal isOpen={isLoginOpen} onClose={() => setIsLoginOpen(false)} />
      </>
    );
  }

  return (
    <div className="relative">
      <button
        onClick={() => setIsDropdownOpen(!isDropdownOpen)}
        className="flex items-center space-x-2 p-1.5 rounded-lg text-text-primary hover:bg-surface-hover transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent"
        aria-expanded={isDropdownOpen}
      >
        {user.picture ? (
          <img src={user.picture} alt={user.name || 'User Avatar'} className="w-8 h-8 rounded-full border border-border-default" />
        ) : (
          <div className="w-8 h-8 rounded-full bg-surface-elevated border border-border-default flex items-center justify-center text-text-primary font-medium text-sm">
            {(user.name || user.email || 'U')[0].toUpperCase()}
          </div>
        )}
        <span className="text-sm font-medium hidden md:inline-block max-w-[120px] truncate">
          {user.name || user.email.split('@')[0]}
        </span>
      </button>

      {isDropdownOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setIsDropdownOpen(false)} />
          <div className="absolute right-0 mt-2 w-56 bg-surface border border-border-default rounded-lg shadow-xl z-50 py-1 divide-y divide-border-subtle">
            <div className="px-4 py-3">
              <p className="text-sm font-medium text-text-primary truncate">{user.name || 'Security Tester'}</p>
              <p className="text-xs text-text-secondary truncate mt-0.5">{user.email}</p>
            </div>
            <div className="py-1">
              <button
                onClick={() => {
                  setIsDropdownOpen(false);
                  logout();
                }}
                className="w-full text-left px-4 py-2 text-sm text-critical hover:bg-surface-hover flex items-center space-x-2 transition-colors"
              >
                <LogOut className="w-4 h-4" />
                <span>Sign Out</span>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
