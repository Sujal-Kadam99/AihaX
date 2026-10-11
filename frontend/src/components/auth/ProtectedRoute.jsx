import { useState } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { AUTH_STATES } from '../../context/AuthContext';
import LoginModal from './LoginModal';
import Skeleton from '../ui/Skeleton';

export default function ProtectedRoute({ children }) {
  const { isAuthenticated, authState } = useAuth();
  const [isLoginOpen, setIsLoginOpen] = useState(true);

  if ([AUTH_STATES.UNKNOWN, AUTH_STATES.AUTHENTICATING, AUTH_STATES.REFRESHING].includes(authState)) {
    return (
      <div className="p-8 max-w-4xl mx-auto space-y-4">
        <Skeleton className="h-10 w-1/3" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="p-12 text-center max-w-md mx-auto my-12 bg-surface border border-border-default rounded-xl shadow-lg space-y-4">
        <h3 className="text-xl font-semibold text-text-primary">Authentication Required</h3>
        <p className="text-sm text-text-secondary">
          You must be signed in with your cloud identity to access this security resource.
        </p>
        <LoginModal isOpen={isLoginOpen} onClose={() => setIsLoginOpen(false)} />
      </div>
    );
  }

  return children;
}
