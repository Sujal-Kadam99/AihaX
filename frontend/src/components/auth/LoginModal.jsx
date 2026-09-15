import { useState } from 'react';
import { useAuth } from '../../hooks/useAuth';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import Alert from '../ui/Alert';

export default function LoginModal({ isOpen, onClose }) {
  const { loginWithMock, error } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [localError, setLocalError] = useState(null);

  const handleGoogleLogin = async () => {
    setIsLoading(true);
    setLocalError(null);
    try {
      // In production desktop app, triggers system browser PKCE.
      // In development mode, executes token assertion flow.
      await loginWithMock('google_user');
      if (onClose) onClose();
    } catch (err) {
      setLocalError(err.message || 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Sign in to AihaX" size="sm">
      <div className="space-y-5 py-2">
        <p className="text-sm text-text-secondary">
          Authenticate with your cloud identity to access automated security scans and reports.
        </p>

        {(error || localError) && (
          <Alert variant="destructive" title="Authentication Error">
            {localError || error}
          </Alert>
        )}

        <div className="space-y-3 pt-2">
          <Button
            variant="outline"
            className="w-full justify-center py-2.5 space-x-3 text-text-primary hover:bg-surface-hover border-border-default"
            onClick={handleGoogleLogin}
            isLoading={isLoading}
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
            <span>Continue with Google</span>
          </Button>
        </div>

        <p className="text-xs text-center text-text-muted pt-2">
          By signing in, you agree to our Terms of Service and Security Code of Conduct.
        </p>
      </div>
    </Modal>
  );
}
