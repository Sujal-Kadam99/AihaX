import { render, screen, act, fireEvent } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AuthProvider, AUTH_STATES } from '../context/AuthContext';
import { useAuth } from '../hooks/useAuth';
import ProtectedRoute from '../components/auth/ProtectedRoute';

vi.mock('../lib/api', () => ({
  getEntitlements: vi.fn().mockResolvedValue({ data: { tier: 'pro' } }),
}));

const localStorageMock = (() => {
  let store = {};
  return {
    getItem: (key) => store[key] || null,
    setItem: (key, value) => {
      store[key] = value.toString();
    },
    removeItem: (key) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
  };
})();

if (typeof window !== 'undefined') {
  Object.defineProperty(window, 'localStorage', {
    value: localStorageMock,
    writable: true,
  });
}

const TestComponent = () => {
  const { user, authState, isAuthenticated, loginWithMock, logout } = useAuth();
  return (
    <div>
      <span data-testid="auth-state">{authState}</span>
      <span data-testid="is-authenticated">{isAuthenticated ? 'YES' : 'NO'}</span>
      <span data-testid="user-email">{user ? user.email : 'NONE'}</span>
      <button onClick={() => loginWithMock('test_user')}>Login Mock</button>
      <button onClick={logout}>Logout</button>
    </div>
  );
};

describe('AuthContext & ProtectedRoute Security Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.localStorage.clear();
  });

  it('initializes to LOGGED_OUT state without exposing tokens in localStorage', () => {
    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    expect(screen.getByTestId('auth-state').textContent).toBe(AUTH_STATES.LOGGED_OUT);
    expect(screen.getByTestId('is-authenticated').textContent).toBe('NO');
    expect(screen.getByTestId('user-email').textContent).toBe('NONE');

    // SECURITY CHECK: Verify zero tokens in browser localStorage
    expect(window.localStorage.getItem('access_token')).toBeNull();
    expect(window.localStorage.getItem('refresh_token')).toBeNull();
    expect(window.localStorage.getItem('id_token')).toBeNull();
  });

  it('updates state to AUTHENTICATED on login while keeping tokens out of localStorage', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: 'mock_jwt_access_token_123',
        refresh_token: 'mock_refresh_token_456',
        user: {
          id: 'u_123',
          google_sub: 'sub_123',
          email: 'test_user@example.com',
          name: 'Test User',
        },
      }),
    }));

    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    await act(async () => {
      fireEvent.click(screen.getByText('Login Mock'));
    });

    expect(screen.getByTestId('auth-state').textContent).toBe(AUTH_STATES.AUTHENTICATED);
    expect(screen.getByTestId('is-authenticated').textContent).toBe('YES');
    expect(screen.getByTestId('user-email').textContent).toBe('test_user@example.com');

    // SECURITY CHECK: Confirm localStorage remains clean of secrets!
    expect(window.localStorage.getItem('access_token')).toBeNull();
    expect(window.localStorage.getItem('refresh_token')).toBeNull();
  });

  it('ProtectedRoute blocks unauthenticated access and renders login prompt', () => {
    render(
      <AuthProvider>
        <ProtectedRoute>
          <div data-testid="protected-content">Secret Dashboard</div>
        </ProtectedRoute>
      </AuthProvider>
    );

    expect(screen.queryByTestId('protected-content')).toBeNull();
    expect(screen.getByText('Authentication Required')).toBeDefined();
  });
});
