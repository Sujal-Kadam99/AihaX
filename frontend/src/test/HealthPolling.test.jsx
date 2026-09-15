import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import Layout from '../components/Layout';
import * as api from '../lib/api';
import { AuthProvider } from '../context/AuthContext';
import { ThemeProvider } from '../context/ThemeContext';
import { BrowserRouter } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  healthCheck: vi.fn(),
  getEntitlements: vi.fn().mockResolvedValue({ data: { plan: 'FREE' } }),
}));

describe('Layout Health Polling & Degraded State', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('polls health once and renders System Ready when Redis and DB are healthy', async () => {
    api.healthCheck.mockResolvedValueOnce({
      data: { status: 'ok', version: '1.0.0', redis: 'ok', database: 'ok' },
    });

    render(
      <BrowserRouter>
        <ThemeProvider>
          <AuthProvider>
            <Layout />
          </AuthProvider>
        </ThemeProvider>
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(api.healthCheck).toHaveBeenCalledTimes(1);
      expect(screen.getByText('System Ready')).toBeDefined();
    });
  });

  it('correctly reports Redis Optional/Degraded when redis is offline', async () => {
    api.healthCheck.mockResolvedValueOnce({
      data: { status: 'ok', version: '1.0.0', redis: 'error', database: 'ok' },
    });

    render(
      <BrowserRouter>
        <ThemeProvider>
          <AuthProvider>
            <Layout />
          </AuthProvider>
        </ThemeProvider>
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Ready (Redis Optional)')).toBeDefined();
    });
  });

  it('correctly reports Backend Disconnected when health endpoint throws network error', async () => {
    api.healthCheck.mockRejectedValueOnce(new Error('Connection refused'));

    render(
      <BrowserRouter>
        <ThemeProvider>
          <AuthProvider>
            <Layout />
          </AuthProvider>
        </ThemeProvider>
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Backend Disconnected')).toBeDefined();
    });
  });
});
