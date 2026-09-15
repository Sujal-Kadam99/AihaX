import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import VerificationEvidence from '../components/VerificationEvidence';

const mockGet = vi.fn();

vi.mock('../lib/api', () => ({
  default: {
    get: (...args) => mockGet(...args),
  },
  api: {
    get: (...args) => mockGet(...args),
  },
}));

describe('VerificationEvidence Component (Phase 21)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders cryptographic verification evidence and differential verdict', async () => {
    mockGet.mockResolvedValue({
      data: {
        success: true,
        data: {
          run_id: 'VRUN-TEST999',
          strategy_id: 'STRAT-CORS-01',
          status: 'CONFIRMED',
          result_details: 'Observed response divergence demonstrates security-relevant behavioral change',
          finding_id: 'FND-TEST123',
          evidence: {
            evidence_id: 'EVD-999',
            request_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
            response_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
            status_code: 200,
            sanitized_request: 'GET /api/test HTTP/1.1\r\nOrigin: https://evil.example.com',
            sanitized_response: 'HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.example.com',
            verifier_version: '1.0.0-phase21',
          },
        },
      },
    });

    render(<VerificationEvidence campaignId="camp-123" verificationId="VRUN-TEST999" />);

    await waitFor(() => {
      expect(screen.getByText('VRUN-TEST999')).toBeDefined();
      expect(screen.getByText('STRAT-CORS-01')).toBeDefined();
      expect(screen.getByText('CONFIRMED')).toBeDefined();
      expect(screen.getByText('FND-TEST123')).toBeDefined();
      expect(screen.getByText('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')).toBeDefined();
    });

    // Test tab toggle to raw response
    const respTab = screen.getByText('Sanitized Response Proof');
    fireEvent.click(respTab);

    await waitFor(() => {
      expect(screen.getByText(/Access-Control-Allow-Origin: https:\/\/evil\.example\.com/)).toBeDefined();
    });
  });
});
