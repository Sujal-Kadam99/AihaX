import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';

import FindingDetail from '../pages/FindingDetail';
import Findings from '../pages/Findings';
import * as api from '../lib/api';

vi.mock('../lib/api', () => ({
  getFindingDetail: vi.fn(),
  reviewFinding: vi.fn(),
  getFindings: vi.fn(),
  getCampaignFindings: vi.fn(),
  getCampaigns: vi.fn(),
}));

describe('Automated Finding Verification Gate UI', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getCampaigns.mockResolvedValue({
      data: { success: true, data: [{ id: 'camp-1', name: 'Authorized Target', target_url: 'https://app.local' }] },
    });
  });

  it('renders VALIDATED finding with multi-dimensional confidence and machine explanation', async () => {
    const mockFinding = {
      id: 'f-val-1',
      title: 'Database Credentials Exposed in Directory Listing',
      vuln_type: 'C006_Directory_Listing',
      severity: 'high',
      affected_url: 'https://app.local/backup/',
      confidence: 85,
      verdict: 'Verified',
      verification_status: 'VALIDATED',
      finding_disposition: 'VALIDATED',
      condition_confidence: 1.0,
      impact_confidence: 0.85,
      reproducibility_confidence: 1.0,
      exploitability_confidence: 0.75,
      policy_eligibility_confidence: 0.9,
      bounty_eligibility: 'ELIGIBLE',
      verification_explanation: JSON.stringify({
        disposition: 'VALIDATED',
        reason: 'Validated: Directory listing exposes sensitive configuration, credentials, or backup files.',
        condition_confidence: 1.0,
        impact_confidence: 0.85,
        reproducibility_confidence: 1.0,
        exploitability_confidence: 0.75,
        policy_eligibility_confidence: 0.9,
        bounty_eligibility: 'ELIGIBLE',
        checklist: {
          has_target: true,
          has_check_id: true,
          passed_fp_gate: true,
          reproducible: true,
          impact_proven: true,
        },
      }),
    };

    api.getFindingDetail.mockResolvedValue({ data: { success: true, data: mockFinding } });

    render(
      <MemoryRouter initialEntries={['/findings/f-val-1']}>
        <Routes>
          <Route path="/findings/:id" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Automated Finding Verification & Quality Gate/i)).toBeDefined();
    });

    expect(screen.getByTestId('automated-verification-gate-card')).toBeDefined();
    expect(screen.getAllByText('VALIDATED').length).toBeGreaterThan(0);
    expect(screen.getByText('ELIGIBLE')).toBeDefined();
    expect(screen.getAllByText('100%').length).toBeGreaterThan(0);
    expect(screen.getAllByText('85%').length).toBeGreaterThan(0);
  });

  it('renders HARDENING_ONLY finding with 0% impact confidence and non-bounty status', async () => {
    const mockFinding = {
      id: 'f-hard-1',
      title: 'Missing Content Security Policy',
      vuln_type: 'C047_Missing_CSP',
      severity: 'low',
      affected_url: 'https://app.local/',
      confidence: 50,
      verdict: 'Hardening Only',
      verification_status: 'HARDENING_ONLY',
      finding_disposition: 'HARDENING_ONLY',
      condition_confidence: 1.0,
      impact_confidence: 0.0,
      reproducibility_confidence: 1.0,
      exploitability_confidence: 0.0,
      policy_eligibility_confidence: 1.0,
      bounty_eligibility: 'INELIGIBLE',
      verification_explanation: JSON.stringify({
        disposition: 'HARDENING_ONLY',
        reason: 'Security header missing in response headers. Technical condition observed but no direct exploitability demonstrated.',
        failed_requirements: ['DIRECT_EXPLOIT_PROOF_REQUIRED_FOR_HEADER_VULN'],
      }),
    };

    api.getFindingDetail.mockResolvedValue({ data: { success: true, data: mockFinding } });

    render(
      <MemoryRouter initialEntries={['/findings/f-hard-1']}>
        <Routes>
          <Route path="/findings/:id" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Automated Finding Verification & Quality Gate/i)).toBeDefined();
    });

    expect(screen.getAllByText('HARDENING_ONLY').length).toBeGreaterThan(0);
    expect(screen.getByText('INELIGIBLE')).toBeDefined();
    expect(screen.getByText(/DIRECT_EXPLOIT_PROOF_REQUIRED_FOR_HEADER_VULN/i)).toBeDefined();
  });

  it('renders explicit VERIFICATION_ERROR state when engine encounters failure', async () => {
    const mockFinding = {
      id: 'f-err-1',
      title: 'Failed Verification Finding',
      vuln_type: 'C068_BOLA',
      severity: 'high',
      affected_url: 'https://app.local/api/items',
      confidence: 0,
      verdict: 'Verification Error',
      verification_status: 'VERIFICATION_ERROR',
      finding_disposition: 'VERIFICATION_ERROR',
      verification_explanation: JSON.stringify({
        disposition: 'VERIFICATION_ERROR',
        reason: 'Verification engine encountered an internal error: Mock network fault',
        failed_requirements: ['VERIFICATION_ENGINE_EXECUTION'],
      }),
    };

    api.getFindingDetail.mockResolvedValue({ data: { success: true, data: mockFinding } });

    render(
      <MemoryRouter initialEntries={['/findings/f-err-1']}>
        <Routes>
          <Route path="/findings/:id" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId('verification-error-card')).toBeDefined();
    });

    expect(screen.getByTestId('verification-error-banner')).toBeDefined();
    expect(screen.getByText(/Automated Verification Failure/i)).toBeDefined();
    expect(screen.getAllByText(/Mock network fault/i).length).toBeGreaterThan(0);
  });

  it('filters findings by canonical disposition states on Findings page', async () => {
    const mockFindings = [
      {
        id: 'f-1',
        title: 'Verified Finding',
        vuln_type: 'C068_IDOR',
        severity: 'high',
        affected_url: 'https://app.local/profile',
        confidence: 85,
        finding_disposition: 'VALIDATED',
        verification_status: 'VALIDATED',
      },
      {
        id: 'f-2',
        title: 'Header Finding',
        vuln_type: 'C002_HEADERS',
        severity: 'low',
        affected_url: 'https://app.local/',
        confidence: 50,
        finding_disposition: 'HARDENING_ONLY',
        verification_status: 'HARDENING_ONLY',
      },
    ];

    api.getCampaigns.mockResolvedValue({
      data: { success: true, data: [] },
    });
    api.getFindings.mockResolvedValue({ data: { success: true, data: mockFindings } });
    api.getCampaignFindings.mockResolvedValue({ data: { success: true, data: mockFindings } });

    render(
      <MemoryRouter initialEntries={['/findings']}>
        <Routes>
          <Route path="/findings" element={<Findings />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Verified Finding')).toBeDefined();
      expect(screen.getByText('Header Finding')).toBeDefined();
    });

    // Select VALIDATED filter
    const statusSelect = screen.getByRole('combobox', { name: '' });
    fireEvent.change(statusSelect, { target: { value: 'VALIDATED' } });

    expect(screen.getByText('Verified Finding')).toBeDefined();
    expect(screen.queryByText('Header Finding')).toBeNull();
  });
});
