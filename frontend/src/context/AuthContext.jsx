import { createContext, useCallback, useEffect, useState } from 'react';
import {
  getEntitlements,
  loginWithGoogle as submitGoogleLogin,
  logoutSession,
  refreshSession,
  setApiSession,
  setApiSessionCallbacks,
} from '../lib/api';

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
      await window.aihax.storeRefreshToken(tokenStr).catch(() => {
        console.warn('Secure refresh-token storage failed.');
      });
    } else if (!tokenStr && window.aihax?.clearRefreshToken) {
      await window.aihax.clearRefreshToken().catch(() => {
        console.warn('Secure refresh-token cleanup failed.');
      });
    }
  }, []);

  const applyRefreshedSession = useCallback(async (result) => {
    setAccessToken(result.access_token);
    await syncRefreshToken(result.refresh_token);
    if (result.user) setUser(result.user);
    setAuthState(AUTH_STATES.AUTHENTICATED);
  }, [syncRefreshToken]);

  useEffect(() => {
    setApiSessionCallbacks({
      onRefreshed: applyRefreshedSession,
      onExpired: async () => {
        setApiSession(null, null);
        setAccessToken(null);
        await syncRefreshToken(null);
        setUser(null);
        setTier('free');
        setAuthState(AUTH_STATES.LOGGED_OUT);
      },
    });
    return () => setApiSessionCallbacks();
  }, [applyRefreshedSession, syncRefreshToken]);

  // Restore the OS-stored refresh token and rotate it before protected pages render.
  useEffect(() => {
    let cancelled = false;
    const initAuth = async () => {
      const storedToken = await window.aihax?.getRefreshToken?.().catch(() => null);
      if (!storedToken) {
        if (!cancelled) setAuthState(AUTH_STATES.LOGGED_OUT);
        return;
      }

      setAuthState(AUTH_STATES.REFRESHING);
      try {
        const { data } = await refreshSession(storedToken);
        if (cancelled) return;
        setApiSession(data.access_token, data.refresh_token);
        await applyRefreshedSession(data);
        const entitlements = await getEntitlements();
        if (!cancelled) setTier(entitlements.data.tier);
      } catch {
        if (cancelled) return;
        setApiSession(null, null);
        await syncRefreshToken(null);
        setAuthState(AUTH_STATES.LOGGED_OUT);
      }
    };
    initAuth();
    return () => { cancelled = true; };
  }, [applyRefreshedSession, syncRefreshToken]);

  const loginWithGoogle = useCallback(async (idToken) => {
    setAuthState(AUTH_STATES.AUTHENTICATING);
    setError(null);

    try {
      const { data: result } = await submitGoogleLogin(idToken);
      if (!result.access_token) throw new Error('Authentication failed');
      setApiSession(result.access_token, result.refresh_token);
      await applyRefreshedSession(result);
      try {
        const entRes = await getEntitlements();
        setTier(entRes.data.tier);
      } catch {
        setTier('free');
      }

      return result.user;
    } catch (err) {
      setError(err.message);
      setAuthState(AUTH_STATES.AUTH_ERROR);
      throw err;
    }
  }, [applyRefreshedSession]);

  const loginWithMock = useCallback(async (mockIdentifier = 'demo_user') => {
    if (!import.meta.env.DEV) throw new Error('Mock sign-in is available only in development builds.');
    return loginWithGoogle(`mock_id_token_${mockIdentifier}`);
  }, [loginWithGoogle]);

  const logout = useCallback(async () => {
    try {
      if (accessToken && refreshToken) {
        await logoutSession(refreshToken).catch(() => {
          console.warn('Server-side session logout failed.');
        });
      }
    } finally {
      setApiSession(null, null);
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

