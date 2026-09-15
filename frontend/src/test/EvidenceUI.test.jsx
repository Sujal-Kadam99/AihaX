import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import Evidence from '../pages/Evidence';
import * as api from '../lib/api';
import { ToastProvider } from '../context/ToastContext';
import { BrowserRouter } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  getCampaigns: vi.fn(),
  getCampaignEvidence: vi.fn(),
  getCampaignExecutionSummary: vi.fn(),
  getCampaignTimeline: vi.fn(),
}));

describe('Evidence UI Component States', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders Loading state and then Loaded state with evidence items', async () => {
    api.getCampaigns.mockResolvedValueOnce({
      data: {
        data: [{ id: 'camp-1', name: 'Eternal-Zomato-Web-001', target_url: 'https://www.zomato.com' }],
      },
    });

    api.getCampaignEvidence.mockResolvedValueOnce({
      data: {
        data: [
          {
            evidence_id: 'EV-1001',
            evidence_type: 'PROOF',
            target_url: 'https://api.zomato.com/v1/auth',
            content_hash: '3ea2702e0505301a91f5e82b7b51f08e458e0a7f14b6e51f8a846c4f03a6bc01',
            request_payload: 'GET /v1/auth HTTP/1.1',
            response_payload: 'HTTP/1.1 200 OK',
          },
        ],
      },
    });

    render(
      <BrowserRouter>
        <ToastProvider>
          <Evidence />
        </ToastProvider>
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('EV-1001')).toBeDefined();
      expect(screen.getByText('https://api.zomato.com/v1/auth')).toBeDefined();
      expect(screen.getByText('PROOF')).toBeDefined();
    });
  });

  it('renders Empty state when campaign has no captured evidence', async () => {
    api.getCampaigns.mockResolvedValueOnce({
      data: {
        data: [{ id: 'camp-1', name: 'Eternal-Zomato-Web-001', target_url: 'https://www.zomato.com' }],
      },
    });

    api.getCampaignEvidence.mockResolvedValueOnce({
      data: {
        data: [],
      },
    });

    render(
      <BrowserRouter>
        <ToastProvider>
          <Evidence />
        </ToastProvider>
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('No evidence captured yet.')).toBeDefined();
      expect(
        screen.getByText(/Evidence will appear after campaign activity produces captured request\/response artifacts/i)
      ).toBeDefined();
    });
  });

  it('renders Error state and allows retry on network failure', async () => {
    api.getCampaigns.mockResolvedValueOnce({
      data: {
        data: [{ id: 'camp-1', name: 'Eternal-Zomato-Web-001', target_url: 'https://www.zomato.com' }],
      },
    });

    api.getCampaignEvidence.mockRejectedValueOnce(new Error('Network Connection Refused'));

    render(
      <BrowserRouter>
        <ToastProvider>
          <Evidence />
        </ToastProvider>
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Unable to load evidence')).toBeDefined();
      expect(screen.getByText('Network Connection Refused')).toBeDefined();
    });

    // Test Retry button
    api.getCampaignEvidence.mockResolvedValueOnce({
      data: {
        data: [
          {
            evidence_id: 'EV-RETRY-01',
            evidence_type: 'REQUEST',
            target_url: 'https://www.zomato.com/api',
            content_hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
          },
        ],
      },
    });

    const retryBtn = screen.getByRole('button', { name: /retry/i });
    fireEvent.click(retryBtn);

    await waitFor(() => {
      expect(screen.getByText('EV-RETRY-01')).toBeDefined();
    });
  });
});
