import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import HuntingQueue from '../components/HuntingQueue';
import { ToastProvider } from '../context/ToastContext';
import * as api from '../lib/api';

vi.mock('../lib/api', () => ({
  getCampaignHuntingRecommendations: vi.fn(),
  logHuntingDecision: vi.fn(),
  getCampaignSurfaceInventory: vi.fn(),
  getCampaignNegativeEvidence: vi.fn(),
}));

describe('Hunting Queue UI Tests (Phase 20)', () => {
  const mockRecommendations = [
    {
      id: 'rec-001',
      target: 'https://account.xiaomi.com',
      check_id: 'C065_Unencrypted_Transmission',
      check_name: 'Cleartext HTTP Transmission',
      category: 'TRANSPORT_SECURITY',
      risk_level: 'SAFE_ACTIVE',
      estimated_requests: 1,
      utility_score: 0.85,
      confidence: 0.95,
      reason: 'Target is HTTP; transport verification prioritized.',
      expected_evidence: 'HTTP status and headers showing plaintext communication.',
      supporting_historical_evidence: 'Historical utility: 0.85',
      authorization_status: 'HUMAN_REVIEW_REQUIRED',
      status: 'PENDING',
      rank: 1,
    },
  ];

  const mockSurface = [
    {
      id: 'surf-001',
      http_method: 'GET',
      normalized_path: '/pass/serviceLogin',
      parameters: ['sid', 'callback'],
      auth_state: 'ANONYMOUS',
      status_code: 200,
    },
  ];

  const mockNegative = [
    {
      id: 'neg-001',
      check_id: 'C070_Security_Headers',
      endpoint: 'https://account.xiaomi.com/',
      verdict: 'NOT_VULNERABLE',
      request_hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      response_hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    },
  ];

  it('renders Human Review disclaimer, target overview, and recommendations', async () => {
    api.getCampaignHuntingRecommendations.mockResolvedValueOnce({
      data: {
        data: {
          recommendations: mockRecommendations,
        },
      },
    });
    api.getCampaignSurfaceInventory.mockResolvedValueOnce({
      data: { data: { surface_entries: mockSurface } },
    });
    api.getCampaignNegativeEvidence.mockResolvedValueOnce({
      data: { data: { negative_evidence: mockNegative } },
    });

    render(
      <ToastProvider>
        <HuntingQueue
          campaignId="camp-123"
          targetUrl="https://account.xiaomi.com"
          requestsUsed={2}
          maxBudget={10}
        />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByText(/HUMAN REVIEW REQUIRED/i)).toBeDefined();
      expect(screen.getByText(/Cleartext HTTP Transmission/i)).toBeDefined();
      expect(screen.getByText(/85%/i)).toBeDefined();
      expect(screen.getByText(/1 req/i)).toBeDefined();
    });
  });

  it('gating modal requires operator confirmation checkbox before approve execution', async () => {
    api.getCampaignHuntingRecommendations.mockResolvedValueOnce({
      data: {
        data: {
          recommendations: mockRecommendations,
        },
      },
    });
    api.getCampaignSurfaceInventory.mockResolvedValueOnce({
      data: { data: { surface_entries: mockSurface } },
    });
    api.getCampaignNegativeEvidence.mockResolvedValueOnce({
      data: { data: { negative_evidence: mockNegative } },
    });
    api.logHuntingDecision.mockResolvedValueOnce({
      data: { success: true },
    });

    render(
      <ToastProvider>
        <HuntingQueue
          campaignId="camp-123"
          targetUrl="https://account.xiaomi.com"
          requestsUsed={2}
          maxBudget={10}
        />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByText(/Cleartext HTTP Transmission/i)).toBeDefined();
    });

    // Click Approve button
    const approveBtn = screen.getByRole('button', { name: /Approve & Review Plan/i });
    fireEvent.click(approveBtn);

    // Modal appears
    await waitFor(() => {
      expect(screen.getByText(/Confirm Action: APPROVE/i)).toBeDefined();
    });

    // Confirm button should be disabled until checkbox checked
    const confirmBtn = screen.getByRole('button', { name: /Confirm APPROVE/i });
    expect(confirmBtn.disabled).toBe(true);

    // Check confirmation box
    const checkbox = screen.getByRole('checkbox');
    fireEvent.click(checkbox);
    expect(confirmBtn.disabled).toBe(false);

    // Click Confirm
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(api.logHuntingDecision).toHaveBeenCalledWith('camp-123', expect.objectContaining({
        recommendation_id: 'rec-001',
        check_id: 'C065_Unencrypted_Transmission',
        decision: 'APPROVE',
      }));
    });
  });

  it('switches between tabs to view surface inventory and negative evidence', async () => {
    api.getCampaignHuntingRecommendations.mockResolvedValueOnce({
      data: { data: { recommendations: mockRecommendations } },
    });
    api.getCampaignSurfaceInventory.mockResolvedValueOnce({
      data: { data: { surface_entries: mockSurface } },
    });
    api.getCampaignNegativeEvidence.mockResolvedValueOnce({
      data: { data: { negative_evidence: mockNegative } },
    });

    render(
      <ToastProvider>
        <HuntingQueue
          campaignId="camp-123"
          targetUrl="https://account.xiaomi.com"
          requestsUsed={2}
          maxBudget={10}
        />
      </ToastProvider>
    );

    // Switch to Surface tab
    const surfaceTab = await screen.findByRole('button', { name: /Surface Inventory/i });
    fireEvent.click(surfaceTab);

    await waitFor(() => {
      expect(screen.getByText('/pass/serviceLogin')).toBeDefined();
    });

    // Switch to Negative Evidence tab
    const negativeTab = screen.getByRole('button', { name: /Negative Evidence/i });
    fireEvent.click(negativeTab);

    await waitFor(() => {
      expect(screen.getByText('C070_Security_Headers')).toBeDefined();
    });
  });
});
