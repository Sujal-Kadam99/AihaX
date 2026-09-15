import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import NewAssessment from '../pages/NewAssessment';
import { ToastProvider } from '../context/ToastContext';
import * as api from '../lib/api';

vi.mock('../lib/api', () => ({
  getPrograms: vi.fn().mockResolvedValue({
    data: {
      data: [
        {
          id: 'prog-001',
          name: 'Authorized Test Program',
          scope: {
            in_scope_assets: ['https://example.com/*'],
            out_of_scope_assets: ['https://evil.com/*'],
          },
        },
      ],
    },
  }),
  validateTargetScope: vi.fn(),
  createCampaign: vi.fn(),
  authorizeCampaign: vi.fn(),
  startCampaign: vi.fn(),
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}));

describe('Scope UI Safety Tests (Section 24)', () => {
  it('displays OUT OF SCOPE — BLOCKED and disables launch when target is out of scope', async () => {
    api.validateTargetScope.mockResolvedValueOnce({
      data: {
        data: {
          allowed: false,
          status: 'OUT_OF_SCOPE',
          reason: 'Target is not in the authorized asset list.',
        },
      },
    });

    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    // Wait for program to load
    await waitFor(() => {
      expect(screen.getByRole('option', { name: /Authorized Test Program/i })).toBeDefined();
    });

    // Enter out-of-scope target
    const targetInput = screen.getByPlaceholderText('https://example-shop.myshopify.com');
    fireEvent.change(targetInput, { target: { value: 'https://evil.com/leak' } });

    // Click Validate Scope
    const validateBtn = screen.getByRole('button', { name: /Validate Scope/i });
    fireEvent.click(validateBtn);

    // Verify OUT OF SCOPE Banner
    await waitFor(() => {
      expect(screen.getByText(/● OUT OF SCOPE — BLOCKED/i)).toBeDefined();
    });

    // Verify Launch button is disabled
    const launchBtn = screen.getByRole('button', { name: /Launch Controlled Assessment/i });
    expect(launchBtn.disabled).toBe(true);
  });

  it('displays SCOPE VALIDATED and enables launch when target is authorized', async () => {
    api.validateTargetScope.mockResolvedValueOnce({
      data: {
        data: {
          allowed: true,
          status: 'IN_SCOPE',
          reason: 'Target matched authorized pattern https://example.com/*',
          matched_rule: '*.example.com',
        },
      },
    });

    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('option', { name: /Authorized Test Program/i })).toBeDefined();
    });

    const targetInput = screen.getByPlaceholderText('https://example-shop.myshopify.com');
    fireEvent.change(targetInput, { target: { value: 'https://example.com/api' } });

    const validateBtn = screen.getByRole('button', { name: /Validate Scope/i });
    fireEvent.click(validateBtn);

    await waitFor(() => {
      expect(screen.getByText(/● SCOPE VALIDATED/i)).toBeDefined();
      expect(screen.getByText(/Authorized by:/i)).toBeDefined();
    });

    const launchBtn = screen.getByRole('button', { name: /Launch Controlled Assessment/i });
    expect(launchBtn.disabled).toBe(false);
  });

  it('rejects wildcard input and blocks launch without sending valid request', async () => {
    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('option', { name: /Authorized Test Program/i })).toBeDefined();
    });

    const targetInput = screen.getByPlaceholderText('https://example-shop.myshopify.com');
    fireEvent.change(targetInput, { target: { value: '*.example.com' } });

    const validateBtn = screen.getByRole('button', { name: /Validate Scope/i });
    fireEvent.click(validateBtn);

    await waitFor(() => {
      expect(screen.getByText(/● INVALID TARGET/i)).toBeDefined();
    });

    const launchBtn = screen.getByRole('button', { name: /Launch Controlled Assessment/i });
    expect(launchBtn.disabled).toBe(true);
  });

  it('invalidates scope validation when target input changes after successful validation', async () => {
    api.validateTargetScope.mockResolvedValueOnce({
      data: {
        data: {
          allowed: true,
          status: 'IN_SCOPE',
          reason: 'Target matched authorized pattern',
          matched_rule: '*.example.com',
        },
      },
    });

    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('option', { name: /Authorized Test Program/i })).toBeDefined();
    });

    const targetInput = screen.getByPlaceholderText('https://example-shop.myshopify.com');
    fireEvent.change(targetInput, { target: { value: 'https://example.com/store' } });

    const validateBtn = screen.getByRole('button', { name: /Validate Scope/i });
    fireEvent.click(validateBtn);

    await waitFor(() => {
      expect(screen.getByText(/● SCOPE VALIDATED/i)).toBeDefined();
    });

    const launchBtn = screen.getByRole('button', { name: /Launch Controlled Assessment/i });
    expect(launchBtn.disabled).toBe(false);

    // User edits target URL
    fireEvent.change(targetInput, { target: { value: 'https://another-domain.com' } });

    // Validation must immediately reset and launch must be disabled
    expect(screen.queryByText(/● SCOPE VALIDATED/i)).toBeNull();
    expect(launchBtn.disabled).toBe(true);
  });

  it('invalidates scope validation when selected program changes', async () => {
    api.validateTargetScope.mockResolvedValueOnce({
      data: {
        data: {
          allowed: true,
          status: 'IN_SCOPE',
          reason: 'Target in scope',
          matched_rule: '*.example.com',
        },
      },
    });

    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('option', { name: /Authorized Test Program/i })).toBeDefined();
    });

    const targetInput = screen.getByPlaceholderText('https://example-shop.myshopify.com');
    fireEvent.change(targetInput, { target: { value: 'https://example.com/api' } });

    const validateBtn = screen.getByRole('button', { name: /Validate Scope/i });
    fireEvent.click(validateBtn);

    await waitFor(() => {
      expect(screen.getByText(/● SCOPE VALIDATED/i)).toBeDefined();
    });

    const launchBtn = screen.getByRole('button', { name: /Launch Controlled Assessment/i });
    expect(launchBtn.disabled).toBe(false);

    // Operator changes selected program
    const programSelect = screen.getAllByRole('combobox')[0];
    fireEvent.change(programSelect, { target: { value: 'prog-001' } });

    // Validation must reset
    expect(screen.queryByText(/● SCOPE VALIDATED/i)).toBeNull();
    expect(launchBtn.disabled).toBe(true);
  });

  it('renders authorized scope rules as read-only badges', async () => {
    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByText(/Authorized Scope Rules \(Authorized Test Program\)/i)).toBeDefined();
      expect(screen.getByText('https://example.com/*')).toBeDefined();
    });
  });
});


