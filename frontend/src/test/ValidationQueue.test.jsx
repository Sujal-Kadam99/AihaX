import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ValidationQueue from '../components/ValidationQueue';
import { ToastProvider } from '../context/ToastContext';

const mockGet = vi.fn();
const mockPost = vi.fn();

vi.mock('../lib/api', () => ({
  default: {
    get: (...args) => mockGet(...args),
    post: (...args) => mockPost(...args),
  },
  api: {
    get: (...args) => mockGet(...args),
    post: (...args) => mockPost(...args),
  },
}));

describe('ValidationQueue Component (Phase 21)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders target information, budget, and generated hypotheses', async () => {
    mockGet.mockImplementation((url) => {
      if (url.includes('/hypotheses')) {
        return Promise.resolve({
          data: {
            success: true,
            data: {
              hypotheses: [
                {
                  hypothesis_id: 'HYP-TEST001',
                  target: 'https://account.example.com',
                  endpoint: 'https://account.example.com/api/test',
                  method: 'GET',
                  parameter: 'id',
                  vulnerability_class: 'IDOR_BOLA',
                  hypothesis: 'Direct object reference observed in parameter id',
                  rationale: 'Parameter id may permit horizontal access',
                  prerequisite_observations: ['Baseline 200 OK'],
                  expected_evidence: 'Differential HTTP status',
                  verification_strategy: 'STRAT-IDOR-01',
                  estimated_requests: 2,
                  risk_level: 'SAFE_ACTIVE',
                  confidence: 0.85,
                  status: 'PENDING',
                },
              ],
            },
          },
        });
      }
      if (url.includes('/verification-budget')) {
        return Promise.resolve({
          data: {
            success: true,
            data: {
              remaining_budget: 8,
              budget_cap: 10,
              requests_used: 2,
            },
          },
        });
      }
      return Promise.reject(new Error('not found'));
    });

    render(<ToastProvider><ValidationQueue campaignId="camp-123" targetUrl="https://account.example.com" /></ToastProvider>);

    await waitFor(() => {
      expect(screen.getByText('https://account.example.com')).toBeDefined();
      expect(screen.getByText('IDOR_BOLA')).toBeDefined();
      expect(screen.getByText('Direct object reference observed in parameter id')).toBeDefined();
      expect(screen.getByText('Cost: 2 req')).toBeDefined();
    });
  });

  it('handles operator reject decision', async () => {
    mockGet.mockImplementation((url) => {
      if (url.includes('/hypotheses')) {
        return Promise.resolve({
          data: {
            success: true,
            data: {
              hypotheses: [
                {
                  hypothesis_id: 'HYP-TEST002',
                  target: 'https://account.example.com',
                  endpoint: 'https://account.example.com/login',
                  method: 'GET',
                  vulnerability_class: 'AUTHENTICATION',
                  hypothesis: 'Check session cookie attributes',
                  rationale: 'Ensure secure flags',
                  prerequisite_observations: [],
                  expected_evidence: 'Set-Cookie headers',
                  verification_strategy: 'STRAT-AUTH-01',
                  estimated_requests: 1,
                  confidence: 0.7,
                  status: 'PENDING',
                },
              ],
            },
          },
        });
      }
      return Promise.resolve({ data: { success: true, data: { remaining_budget: 10, budget_cap: 10, requests_used: 0 } } });
    });

    mockPost.mockResolvedValue({ data: { success: true, data: { decision: 'REJECT' } } });

    render(<ToastProvider><ValidationQueue campaignId="camp-123" targetUrl="https://account.example.com" /></ToastProvider>);

    await waitFor(() => {
      expect(screen.getByText('Reject')).toBeDefined();
    });

    fireEvent.click(screen.getByText('Reject'));

    await waitFor(() => {
      expect(screen.getByText('Confirm Rejection')).toBeDefined();
    });

    fireEvent.click(screen.getByText('Confirm Rejection'));

    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledWith(
        '/api/campaigns/camp-123/hypotheses/HYP-TEST002/decision',
        expect.objectContaining({ decision: 'REJECT' })
      );
    });
  });
});
