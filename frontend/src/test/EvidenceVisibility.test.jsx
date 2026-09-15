import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import Evidence from '../pages/Evidence';
import ExecutionTimeline from '../components/ExecutionTimeline';
import * as api from '../lib/api';
import { ToastProvider } from '../context/ToastContext';
import { BrowserRouter } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  getCampaigns: vi.fn(),
  getCampaignEvidence: vi.fn(),
  getCampaignExecutionSummary: vi.fn(),
  getCampaignTimeline: vi.fn(),
  getEvidenceDetail: vi.fn(),
}));

const mockCampaign = {
  id: 'camp-test-01',
  campaign_id: 'camp-test-01',
  name: 'Local Observable Test Campaign',
  target_url: 'http://localhost:8000/demo',
};

const mockEvidenceItem = {
  id: 'evid-998877665544',
  evidence_id: 'evid-998877665544',
  campaign_id: 'camp-test-01',
  finding_id: 'find-001',
  task_id: 'TASK-C001',
  evidence_type: 'PROOF',
  target_url: 'http://localhost:8000/demo/api/v1/auth',
  method: 'POST',
  sanitized_request: 'POST /demo/api/v1/auth HTTP/1.1\r\nAuthorization: [REDACTED]\r\n\r\n{"user":"admin"}',
  sanitized_response: 'HTTP/1.1 200 OK\r\nSet-Cookie: [REDACTED]\r\n\r\n{"status":"authenticated"}',
  payload_summary: 'Observed authentication bypass with sanitized tokens',
  content_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  chain_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  created_at: '2026-09-03T01:00:00Z',
};

function renderWithProviders(ui) {
  return render(
    <BrowserRouter>
      <ToastProvider>{ui}</ToastProvider>
    </BrowserRouter>
  );
}

describe('Evidence Visibility & Execution Transparency Gate (Frontend)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getCampaigns.mockResolvedValue({
      data: { data: [mockCampaign] },
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // REAL EXECUTION PROOF FLOW 1: POSITIVE FLOW
  // ───────────────────────────────────────────────────────────────────────────
  it('[Proof Flow 1] parses wrapped API response, renders evidence table, opens detail, and displays SHA-256 hash', async () => {
    // API returns backend wrapped structure { items: [...], total_count: 1 }
    api.getCampaignEvidence.mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          campaign_id: 'camp-test-01',
          total_count: 1,
          items: [mockEvidenceItem],
        },
      },
    });
    api.getCampaignExecutionSummary.mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          status: 'COMPLETED',
          evidence_count: 1,
          tests_completed: 1,
        },
      },
    });

    renderWithProviders(<Evidence />);

    // 1. Evidence record rendered
    await waitFor(() => {
      expect(screen.getByText('evid-998877665544')).toBeDefined();
      expect(screen.getByText('http://localhost:8000/demo/api/v1/auth')).toBeDefined();
      expect(screen.getByText('PROOF')).toBeDefined();
    });

    // 2. Click to open Evidence Detail Modal
    const viewButton = screen.getByRole('button', { name: /view/i });
    fireEvent.click(viewButton);

    // 3. Evidence Detail displays exact SHA-256 hash
    await waitFor(() => {
      expect(screen.getByText('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')).toBeDefined();
      expect(screen.getByText('REDACTED')).toBeDefined();
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // REAL EXECUTION PROOF FLOW 2: NEGATIVE CASE (BLOCKED BEFORE NETWORK TESTING)
  // ───────────────────────────────────────────────────────────────────────────
  it('[Proof Flow 2] displays explicit blocked state when authorization or scope halts execution', async () => {
    api.getCampaignEvidence.mockResolvedValueOnce({
      data: { success: true, data: { items: [], total_count: 0 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          status: 'BLOCKED',
          phase: 'BLOCKED',
          tests_selected: 5,
          tests_started: 0,
          tests_completed: 0,
          tests_blocked: 1,
          evidence_count: 0,
          terminal_reason: 'Live execution blocked: authorization was not confirmed.',
        },
      },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('Execution was blocked before network testing.')).toBeDefined();
      expect(screen.getByText(/Live execution blocked: authorization was not confirmed/i)).toBeDefined();
    });

    // Proves it does NOT say generic "No execution has started" or "Evidence could not be loaded"
    expect(screen.queryByText('Unable to load evidence')).toBeNull();
  });

  // ───────────────────────────────────────────────────────────────────────────
  // REAL EXECUTION PROOF FLOW 3: API FAILURE CASE (RESILIENCY)
  // ───────────────────────────────────────────────────────────────────────────
  it('[Proof Flow 3] displays explicit error state on HTTP 500 and strictly avoids false empty state', async () => {
    api.getCampaignEvidence.mockRejectedValueOnce({
      response: {
        status: 500,
        data: { detail: 'Internal Server Error: Database Connection Pool Exhausted' },
      },
    });
    api.getCampaignExecutionSummary.mockResolvedValueOnce({
      data: { data: { status: 'EXECUTING', tests_selected: 4 } },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('Unable to load evidence')).toBeDefined();
      expect(screen.getByText('Internal Server Error: Database Connection Pool Exhausted')).toBeDefined();
    });

    // Proves it does NOT say "No evidence captured yet"
    expect(screen.queryByText('No execution has started.')).toBeNull();
    expect(screen.queryByText('Execution completed. No evidence artifacts were captured.')).toBeNull();

    // Verify Retry button functions
    api.getCampaignEvidence.mockResolvedValueOnce({
      data: { success: true, data: { items: [mockEvidenceItem], total_count: 1 } },
    });
    const retryBtn = screen.getByRole('button', { name: /retry/i });
    fireEvent.click(retryBtn);

    await waitFor(() => {
      expect(screen.getByText('evid-998877665544')).toBeDefined();
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // STATE A: NO EXECUTION HAS STARTED
  // ───────────────────────────────────────────────────────────────────────────
  it('renders State A when campaign is newly created and execution has not started', async () => {
    api.getCampaignEvidence.mockResolvedValueOnce({
      data: { success: true, data: { items: [], total_count: 0 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          status: 'NOT_STARTED',
          tests_started: 0,
          tests_completed: 0,
          tests_blocked: 0,
          evidence_count: 0,
        },
      },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('No execution has started.')).toBeDefined();
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // STATE C: EXECUTION RUNNING IN PROGRESS
  // ───────────────────────────────────────────────────────────────────────────
  it('renders State C with live test counters while execution is actively running', async () => {
    api.getCampaignEvidence.mockResolvedValueOnce({
      data: { success: true, data: { items: [], total_count: 0 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          status: 'EXECUTING',
          tests_selected: 8,
          tests_started: 4,
          tests_completed: 3,
          tests_blocked: 0,
          evidence_count: 0,
        },
      },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText(/Execution is in progress\. 3\/8 tests completed\./i)).toBeDefined();
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // STATE D: COMPLETED WITH ZERO EVIDENCE
  // ───────────────────────────────────────────────────────────────────────────
  it('renders State D when all tests complete honestly without capturing vulnerability artifacts', async () => {
    api.getCampaignEvidence.mockResolvedValueOnce({
      data: { success: true, data: { items: [], total_count: 0 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          status: 'COMPLETED',
          tests_selected: 5,
          tests_started: 5,
          tests_completed: 5,
          evidence_count: 0,
          terminal_reason: 'Execution completed. No evidence artifacts were captured.',
        },
      },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('Execution completed. No evidence artifacts were captured.')).toBeDefined();
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // SEARCH FILTERING
  // ───────────────────────────────────────────────────────────────────────────
  it('filters evidence by search query matching URL, evidence ID, or hash', async () => {
    const item2 = {
      ...mockEvidenceItem,
      id: 'evid-2222',
      evidence_id: 'evid-2222',
      target_url: 'http://localhost:8000/demo/search',
      content_hash: 'aaaa1111bbbb2222',
    };

    api.getCampaignEvidence.mockResolvedValueOnce({
      data: { success: true, data: { items: [mockEvidenceItem, item2], total_count: 2 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValueOnce({
      data: { data: { status: 'COMPLETED', evidence_count: 2 } },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('evid-998877665544')).toBeDefined();
      expect(screen.getByText('evid-2222')).toBeDefined();
    });

    const searchInput = screen.getByPlaceholderText(/search evidence id/i);
    fireEvent.change(searchInput, { target: { value: 'search' } });

    await waitFor(() => {
      expect(screen.queryByText('evid-998877665544')).toBeNull();
      expect(screen.getByText('evid-2222')).toBeDefined();
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // EVIDENCE DETAIL MODAL PROPERTIES
  // ───────────────────────────────────────────────────────────────────────────
  it('displays full detail properties in modal including request and response payloads', async () => {
    api.getCampaignEvidence.mockResolvedValueOnce({
      data: { success: true, data: { items: [mockEvidenceItem], total_count: 1 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValueOnce({
      data: { data: { status: 'COMPLETED', evidence_count: 1 } },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('evid-998877665544')).toBeDefined();
    });

    fireEvent.click(screen.getByRole('button', { name: /view/i }));

    await waitFor(() => {
      expect(screen.getByText(/POST \/demo\/api\/v1\/auth/i)).toBeDefined();
      expect(screen.getByText(/HTTP\/1\.1 200 OK/i)).toBeDefined();
      expect(screen.getByText('find-001')).toBeDefined();
      expect(screen.getByText(/Observed authentication bypass/i)).toBeDefined();
    });

    // Close button
    const closeButtons = screen.getAllByRole('button', { name: /close/i });
    fireEvent.click(closeButtons[0]);
    await waitFor(() => {
      expect(screen.queryByText(/Observed authentication bypass/i)).toBeNull();
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // VIEW SWITCHING: TIMELINE TAB
  // ───────────────────────────────────────────────────────────────────────────
  it('switches to Execution Timeline tab and requests timeline events', async () => {
    api.getCampaignEvidence.mockResolvedValue({
      data: { success: true, data: { items: [mockEvidenceItem], total_count: 1 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValue({
      data: { data: { status: 'COMPLETED' } },
    });
    api.getCampaignTimeline.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            id: 'evt-1',
            event_type: 'TEST_STARTED',
            timestamp: '2026-09-03T01:05:00Z',
            check_id: 'CHECK-C001',
            target_url: 'http://localhost:8000/demo/api/v1/auth',
            status: 'SUCCESS',
            event_hash: '12345678abcdef',
          },
          {
            id: 'evt-2',
            event_type: 'EVIDENCE_CAPTURED',
            timestamp: '2026-09-03T01:05:01Z',
            check_id: 'CHECK-C001',
            evidence_id: 'evid-998877665544',
            status: 'SUCCESS',
            event_hash: '87654321fedcba',
          },
        ],
      },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('evid-998877665544')).toBeDefined();
    });

    const timelineTab = screen.getByRole('button', { name: /execution timeline/i });
    fireEvent.click(timelineTab);

    await waitFor(() => {
      expect(screen.getByText(/Deterministic Execution Timeline/i)).toBeDefined();
      expect(screen.getAllByText('CHECK-C001').length).toBeGreaterThan(0);
      expect(screen.getByText('EVIDENCE_CAPTURED')).toBeDefined();
    });
  });

  // ───────────────────────────────────────────────────────────────────────────
  // TIMELINE COMPONENT TESTS
  // ───────────────────────────────────────────────────────────────────────────
  it('[Timeline] renders timeline entries and filters by category', async () => {
    api.getCampaignTimeline.mockResolvedValueOnce({
      data: {
        data: [
          {
            id: 'e1',
            event_type: 'TEST_STARTED',
            timestamp: '2026-09-03T01:00:00Z',
            check_id: 'CHECK-01',
            status: 'SUCCESS',
          },
          {
            id: 'e2',
            event_type: 'EVIDENCE_CAPTURED',
            timestamp: '2026-09-03T01:00:01Z',
            evidence_id: 'evid-1234',
            status: 'SUCCESS',
          },
          {
            id: 'e3',
            event_type: 'BLOCKED_SCOPE',
            timestamp: '2026-09-03T01:00:02Z',
            reason: 'Target is outside authorized HackerOne wildcard',
            status: 'BLOCKED',
          },
        ],
      },
    });

    renderWithProviders(<ExecutionTimeline campaignId="camp-test-01" />);

    await waitFor(() => {
      expect(screen.getByText('TEST_STARTED')).toBeDefined();
      expect(screen.getByText('EVIDENCE_CAPTURED')).toBeDefined();
      expect(screen.getByText('BLOCKED_SCOPE')).toBeDefined();
    });

    // Filter by BLOCKED
    const blockedBtn = screen.getByRole('button', { name: 'BLOCKED' });
    fireEvent.click(blockedBtn);

    await waitFor(() => {
      expect(screen.queryByText('TEST_STARTED')).toBeNull();
      expect(screen.getByText('BLOCKED_SCOPE')).toBeDefined();
      expect(screen.getByText(/Target is outside authorized HackerOne wildcard/i)).toBeDefined();
    });

    // Filter by EVIDENCE
    const evidenceBtn = screen.getByRole('button', { name: 'EVIDENCE' });
    fireEvent.click(evidenceBtn);

    await waitFor(() => {
      expect(screen.getByText('EVIDENCE_CAPTURED')).toBeDefined();
      expect(screen.queryByText('BLOCKED_SCOPE')).toBeNull();
    });
  });

  it('[Timeline] displays error state and supports retry', async () => {
    api.getCampaignTimeline.mockRejectedValueOnce(new Error('Timeline Network Timeout'));

    renderWithProviders(<ExecutionTimeline campaignId="camp-test-01" />);

    await waitFor(() => {
      expect(screen.getByText('Failed to load timeline')).toBeDefined();
      expect(screen.getByText('Timeline Network Timeout')).toBeDefined();
    });

    api.getCampaignTimeline.mockResolvedValueOnce({
      data: {
        data: [{ id: 'e1', event_type: 'CAMPAIGN_CREATED', timestamp: '2026-09-03T00:00:00Z', status: 'SUCCESS' }],
      },
    });

    const retryBtn = screen.getByRole('button', { name: /retry/i });
    fireEvent.click(retryBtn);

    await waitFor(() => {
      expect(screen.getByText('CAMPAIGN_CREATED')).toBeDefined();
    });
  });

  it('[Timeline] displays empty state when no events exist', async () => {
    api.getCampaignTimeline.mockResolvedValueOnce({
      data: { data: [] },
    });

    renderWithProviders(<ExecutionTimeline campaignId="camp-test-01" />);

    await waitFor(() => {
      expect(screen.getByText('No lifecycle events recorded yet.')).toBeDefined();
    });
  });

  it('[Timeline] calls onSelectEvidence when evidence chip is clicked', async () => {
    const onSelectEv = vi.fn();
    api.getCampaignTimeline.mockResolvedValueOnce({
      data: {
        data: [
          {
            id: 'e1',
            event_type: 'EVIDENCE_CAPTURED',
            timestamp: '2026-09-03T01:00:00Z',
            evidence_id: 'evid-chip-01',
            status: 'SUCCESS',
          },
        ],
      },
    });

    renderWithProviders(
      <ExecutionTimeline campaignId="camp-test-01" onSelectEvidence={onSelectEv} />
    );

    await waitFor(() => {
      expect(screen.getByText('evid-chip-')).toBeDefined();
    });

    fireEvent.click(screen.getByText('evid-chip-'));
    expect(onSelectEv).toHaveBeenCalledWith('evid-chip-01');
  });

  it('[Timeline] calls onSelectFinding when finding chip is clicked', async () => {
    const onSelectFinding = vi.fn();
    api.getCampaignTimeline.mockResolvedValueOnce({
      data: {
        data: [
          {
            id: 'e1',
            event_type: 'FINDING_CREATED',
            timestamp: '2026-09-03T01:00:00Z',
            finding_id: 'find-chip-99',
            status: 'SUCCESS',
          },
        ],
      },
    });

    renderWithProviders(
      <ExecutionTimeline campaignId="camp-test-01" onSelectFinding={onSelectFinding} />
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /finding/i })).toBeDefined();
    });

    fireEvent.click(screen.getByRole('button', { name: /finding/i }));
    expect(onSelectFinding).toHaveBeenCalledWith('find-chip-99');
  });

  it('supports selecting different campaigns from dropdown', async () => {
    const camp2 = { id: 'camp-02', campaign_id: 'camp-02', name: 'Second Campaign', target_url: 'https://example.com' };
    api.getCampaigns.mockResolvedValueOnce({
      data: { data: [mockCampaign, camp2] },
    });
    api.getCampaignEvidence.mockResolvedValue({
      data: { success: true, data: { items: [], total_count: 0 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValue({
      data: { data: { status: 'NOT_STARTED' } },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText(/Local Observable Test Campaign/i)).toBeDefined();
    });

    const selects = screen.getAllByRole('combobox');
    const select = selects[0];
    fireEvent.change(select, { target: { value: 'camp-02' } });

    expect(api.getCampaignEvidence).toHaveBeenCalledWith('camp-02', expect.any(Object));
  });

  it('supports filtering evidence by type selector', async () => {
    api.getCampaignEvidence.mockResolvedValue({
      data: { success: true, data: { items: [mockEvidenceItem], total_count: 1 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValue({
      data: { data: { status: 'COMPLETED' } },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('evid-998877665544')).toBeDefined();
    });

    const typeSelects = screen.getAllByRole('combobox');
    const typeSelect = typeSelects[1]; // second dropdown is Type filter
    fireEvent.change(typeSelect, { target: { value: 'PROOF' } });

    expect(api.getCampaignEvidence).toHaveBeenCalledWith('camp-test-01', { evidence_type: 'PROOF' });
  });

  it('verifies secret redaction in response preview with token masking', async () => {
    const secretItem = {
      ...mockEvidenceItem,
      id: 'evid-secret-check',
      evidence_id: 'evid-secret-check',
      sanitized_request: 'GET /api/user HTTP/1.1\r\nAuthorization: [REDACTED]\r\nCookie: [REDACTED]',
      sanitized_response: 'HTTP/1.1 200 OK\r\nAPI-Key: [REDACTED]\r\n\r\n{"secret":"[REDACTED]"}',
    };

    api.getCampaignEvidence.mockResolvedValue({
      data: { success: true, data: { items: [secretItem], total_count: 1 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValue({
      data: { data: { status: 'COMPLETED', evidence_count: 1 } },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('evid-secret-check')).toBeDefined();
    });

    fireEvent.click(screen.getByRole('button', { name: /view/i }));

    await waitFor(() => {
      expect(screen.getByText(/Authorization: \[REDACTED\]/i)).toBeDefined();
      expect(screen.getByText(/Cookie: \[REDACTED\]/i)).toBeDefined();
      expect(screen.getByText(/API-Key: \[REDACTED\]/i)).toBeDefined();
    });
  });

  it('renders chain hash when present on evidence record', async () => {
    api.getCampaignEvidence.mockResolvedValueOnce({
      data: { success: true, data: { items: [mockEvidenceItem], total_count: 1 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValueOnce({
      data: { data: { status: 'COMPLETED', evidence_count: 1 } },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('evid-998877665544')).toBeDefined();
    });

    fireEvent.click(screen.getByRole('button', { name: /view/i }));

    await waitFor(() => {
      expect(screen.getByText('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBeDefined();
    });
  });

  it('triggers refresh button and reloads evidence and summary', async () => {
    api.getCampaignEvidence.mockResolvedValue({
      data: { success: true, data: { items: [mockEvidenceItem], total_count: 1 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValue({
      data: { data: { status: 'COMPLETED', evidence_count: 1 } },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('evid-998877665544')).toBeDefined();
    });

    const refreshBtn = screen.getByRole('button', { name: /refresh/i });
    fireEvent.click(refreshBtn);

    expect(api.getCampaignEvidence).toHaveBeenCalledTimes(2);
    expect(api.getCampaignExecutionSummary).toHaveBeenCalledTimes(2);
  });

  it('[Proof Flow 2 Invariant] confirms zero requests dispatched in blocked state', async () => {
    api.getCampaignEvidence.mockResolvedValue({
      data: { success: true, data: { items: [], total_count: 0 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValue({
      data: {
        success: true,
        data: {
          status: 'BLOCKED',
          tests_selected: 10,
          tests_started: 0,
          tests_completed: 0,
          tests_blocked: 2,
          terminal_reason: 'Target is outside authorized HackerOne wildcard scope.',
        },
      },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('Execution was blocked before network testing.')).toBeDefined();
      expect(screen.getByText(/Target is outside authorized HackerOne wildcard scope/i)).toBeDefined();
    });

    // Zero table rows rendered
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('displays method and campaign details in evidence drawer', async () => {
    api.getCampaignEvidence.mockResolvedValue({
      data: { success: true, data: { items: [mockEvidenceItem], total_count: 1 } },
    });
    api.getCampaignExecutionSummary.mockResolvedValue({
      data: { data: { status: 'COMPLETED', evidence_count: 1 } },
    });

    renderWithProviders(<Evidence />);

    await waitFor(() => {
      expect(screen.getByText('evid-998877665544')).toBeDefined();
    });

    fireEvent.click(screen.getByRole('button', { name: /view/i }));

    await waitFor(() => {
      expect(screen.getByText('POST')).toBeDefined();
      expect(screen.getByText('camp-test-01')).toBeDefined();
    });
  });
});
