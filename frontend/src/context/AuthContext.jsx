import { createContext, useCallback, useEffect, useState } from 'react';
import { getEntitlements } from '../lib/api';

export const AUTH_STATES = {
  UNKNOWN: 'UNKNOWN',
  AUTHENTICATING: 'AUTHENTICATING',
  AUTHENTICATED: 'AUTHENTICATED',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  REFRESHING: 'REFRESHING',
  LOGGED_OUT: 'LOGGED_OUT',
  AUTH_ERROR: 'AUTH_ERROR',
  OFFLINE_GRACE: 'OFFLINE_GRACE',
};

export const AuthContext = createContext({
  authState: AUTH_STATES.UNKNOWN,
  user: null,
  tier: 'free',
  accessToken: null,
  error: null,
  loginWithGoogle: async () => {},
  loginWithMock: async () => {},
  logout: async () => {},
});

export const AuthProvider = ({ children }) => {
  const [authState, setAuthState] = useState(AUTH_STATES.UNKNOWN);
  const [user, setUser] = useState(null);
  const [tier, setTier] = useState('free');
  const [accessToken, setAccessToken] = useState(null); // STRICTLY IN MEMORY
  const [refreshToken, setRefreshTokenState] = useState(null);
  const [error, setError] = useState(null);

  // Helper to sync refresh token to OS safeStorage (Electron) or Memory (Web)
  const syncRefreshToken = useCallback(async (tokenStr) => {
    setRefreshTokenState(tokenStr);
    if (tokenStr && window.aihax?.storeRefreshToken) {
      await window.aihax.storeRefreshToken(tokenStr).catch(() => {});
    } else if (!tokenStr && window.aihax?.clearRefreshToken) {
      await window.aihax.clearRefreshToken().catch(() => {});
    }
  }, []);

  // Initialize Auth State on Mount
  useEffect(() => {
    const initAuth = async () => {
      let storedToken = refreshToken;
      if (!storedToken && window.aihax?.getRefreshToken) {
        storedToken = await window.aihax.getRefreshToken().catch(() => null);
        if (storedToken) setRefreshTokenState(storedToken);
      }

      if (!accessToken && !storedToken) {
        setAuthState(AUTH_STATES.LOGGED_OUT);
      } else if (accessToken) {
        // Fetch entitlements on active token
        getEntitlements()
          .then((res) => setTier(res.data.tier))
          .catch(() => setTier('free'));
      }
    };
    initAuth();
  }, [accessToken, refreshToken]);

  const loginWithGoogle = useCallback(async (idToken) => {
    setAuthState(AUTH_STATES.AUTHENTICATING);
    setError(null);

    try {
      const response = await fetch('/api/auth/google/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id_token: idToken }),
      });

      const result = await response.json();
      if (!response.ok || !result.access_token) {
        throw new Error(result.detail || (result.error && result.error.message) || 'Authentication failed');
      }

      setAccessToken(result.access_token);
      await syncRefreshToken(result.refresh_token);
      setUser(result.user);
      
      try {
        const entRes = await getEntitlements();
        setTier(entRes.data.tier);
      } catch (err) {
        setTier('free');
      }

      setAuthState(AUTH_STATES.AUTHENTICATED);
      return result.user;
    } catch (err) {
      setError(err.message);
      setAuthState(AUTH_STATES.AUTH_ERROR);
      throw err;
    }
  }, [syncRefreshToken]);

  const loginWithMock = useCallback(async (mockIdentifier = 'demo_user') => {
    return loginWithGoogle(`mock_id_token_${mockIdentifier}`);
  }, [loginWithGoogle]);

  const logout = useCallback(async () => {
    try {
      if (accessToken && refreshToken) {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${accessToken}`,
          },
          body: JSON.stringify({ refresh_token: refreshToken }),
        }).catch(() => {});
      }
    } finally {
      setAccessToken(null);
      await syncRefreshToken(null);
      setUser(null);
      setTier('free');
      setError(null);
      setAuthState(AUTH_STATES.LOGGED_OUT);
    }
  }, [accessToken, refreshToken, syncRefreshToken]);

  return (
    <AuthContext.Provider
      value={{
        authState,
        user,
        tier,
        accessToken,
        error,
        loginWithGoogle,
        loginWithMock,
        logout,
        isAuthenticated: authState === AUTH_STATES.AUTHENTICATED || authState === AUTH_STATES.OFFLINE_GRACE,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export { useAuth } from '../hooks/useAuth';

