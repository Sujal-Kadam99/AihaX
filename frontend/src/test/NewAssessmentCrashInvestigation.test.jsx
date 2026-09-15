import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import NewAssessment from '../pages/NewAssessment';
import {
  normalizeScopeRules,
  normalizeMatchedRule,
  normalizeReason,
} from '../utils/scopeNormalizers';
import { ToastProvider } from '../context/ToastContext';
import * as api from '../lib/api';

vi.mock('../lib/api', () => ({
  getPrograms: vi.fn(),
  validateTargetScope: vi.fn(),
  createCampaign: vi.fn(),
  authorizeCampaign: vi.fn(),
  startCampaign: vi.fn(),
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}));

const defaultProgram = {
  id: 'prog-mit2',
  name: 'mit2+',
  scope: {
    in_scope_assets: ['https://mitacsc.ac.in/'],
    out_of_scope_assets: [],
  },
};

async function validateTargetHelper(targetUrl = 'https://mitacsc.ac.in/') {
  const targetInput = screen.getByPlaceholderText('https://example-shop.myshopify.com');
  fireEvent.change(targetInput, { target: { value: targetUrl } });

  await waitFor(() => {
    const validateBtn = screen.getByRole('button', { name: /Validate Scope/i });
    expect(validateBtn.disabled).toBe(false);
  });
  fireEvent.click(screen.getByRole('button', { name: /Validate Scope/i }));

  await waitFor(() => {
    expect(screen.getByText(/● SCOPE VALIDATED/i)).toBeDefined();
  });
}

describe('NewAssessment Crash Investigation & Resilience Suite', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    api.getPrograms.mockResolvedValue({
      data: {
        data: [defaultProgram],
      },
    });
    api.validateTargetScope.mockResolvedValue({
      data: {
        data: {
          allowed: true,
          status: 'IN_SCOPE',
          reason: "URL matches in-scope URL rule 'https://mitacsc.ac.in/'",
          matched_rule: 'https://mitacsc.ac.in/',
          asset: 'https://mitacsc.ac.in/',
        },
      },
    });
  });

  // Test 1: Valid concrete target + valid scope renders normally
  it('1. Valid concrete target + valid scope renders normally', async () => {
    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /New Security Assessment/i })).toBeDefined();
      expect(screen.getByPlaceholderText('https://example-shop.myshopify.com')).toBeDefined();
      expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
    });

    const targetInput = screen.getByPlaceholderText('https://example-shop.myshopify.com');
    fireEvent.change(targetInput, { target: { value: 'https://mitacsc.ac.in/' } });
    expect(targetInput.value).toBe('https://mitacsc.ac.in/');
  });

  // Test 2: Scope validation success renders normally
  it('2. Scope validation success renders normally', async () => {
    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
    });

    await validateTargetHelper('https://mitacsc.ac.in/');

    expect(screen.getByText(/Target is explicitly authorized for this assessment/i)).toBeDefined();
    expect(screen.getAllByText(/https:\/\/mitacsc\.ac\.in\//i).length).toBeGreaterThan(0);
  });

  // Test 3: Scope rule with one URL renders normally
  it('3. Scope rule with one URL renders normally', async () => {
    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByText(/Authorized Scope Rules \(mit2\+\)/i)).toBeDefined();
      expect(screen.getByText('https://mitacsc.ac.in/')).toBeDefined();
    });
  });

  // Test 4: Scope rule with wildcard renders normally as authorization boundary
  it('4. Scope rule with wildcard renders normally as authorization boundary', async () => {
    api.getPrograms.mockResolvedValueOnce({
      data: {
        data: [
          {
            id: 'prog-wildcard',
            name: 'Wildcard Program',
            scope: {
              in_scope_assets: ['*.shopify.com'],
              out_of_scope: [],
            },
          },
        ],
      },
    });

    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByText(/Authorized Scope Rules \(Wildcard Program\)/i)).toBeDefined();
      expect(screen.getByText('*.shopify.com')).toBeDefined();
      expect(screen.getByText(/Scope wildcard patterns \(e\.g\. \*\.shopify\.com\) define authorization boundaries/i)).toBeDefined();
    });
  });

  // Test 5: Missing optional readiness field does not crash
  it('5. Missing optional readiness field does not crash', async () => {
    api.validateTargetScope.mockResolvedValue({
      data: {
        data: {
          allowed: true,
          status: 'IN_SCOPE',
          reason: null, // missing reason
          matched_rule: null, // missing matched_rule
        },
      },
    });

    api.getPrograms.mockResolvedValue({
      data: {
        data: [
          {
            id: 'prog-mit2',
            name: 'mit2+',
            scope: { in_scope_assets: ['https://mitacsc.ac.in/'] },
            policy_url: null,
          },
        ],
      },
    });

    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
    });

    await validateTargetHelper('https://mitacsc.ac.in/');

    // Readiness section must render cleanly without throwing
    expect(screen.getByText(/PRE-FLIGHT READINESS/i)).toBeDefined();
    expect(screen.getAllByText(/mit2\+/i).length).toBeGreaterThan(0);
  });

  // Test 6: Missing scope rule data does not crash
  it('6. Missing scope rule data does not crash', async () => {
    // Scope is null or missing in_scope_assets
    api.getPrograms.mockResolvedValue({
      data: {
        data: [
          {
            id: 'prog-empty-scope',
            name: 'Empty Scope Program',
            scope: null,
          },
          {
            id: 'prog-object-scope',
            name: 'Object Scope Program',
            scope: {
              in_scope_assets: [
                { asset_name: 'mit-asset', raw_scope_definition: 'https://mitacsc.ac.in/' },
              ],
            },
          },
        ],
      },
    });

    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByText(/No scope rules defined for this program/i)).toBeDefined();
    });

    // Switch to program with structured object scope assets
    const programSelect = screen.getByLabelText(/Authorized Scope Program/i);
    fireEvent.change(programSelect, { target: { value: 'prog-object-scope' } });

    await waitFor(() => {
      expect(screen.getByText('https://mitacsc.ac.in/')).toBeDefined();
    });
  });

  // Test 7: API error renders explicit error state
  it('7. API error renders explicit error state', async () => {
    api.getPrograms.mockRejectedValueOnce({
      response: {
        status: 500,
        data: { error: { message: 'Internal Server Error: Database disconnected' } },
      },
    });

    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByText(/API Error: Scope Programs Unavailable/i)).toBeDefined();
      expect(screen.getByText(/Internal Server Error: Database disconnected/i)).toBeDefined();
      expect(screen.getByRole('button', { name: /Retry Connection/i })).toBeDefined();
    });
  });

  // Test 8: Authorization PASS renders normally
  it('8. Authorization PASS renders normally', async () => {
    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
    });

    await validateTargetHelper('https://mitacsc.ac.in/');

    expect(screen.getByText(/PASS \(30d Active\)/i)).toBeDefined();
  });

  // Test 9: Destination Safety PASS renders normally
  it('9. Destination Safety PASS renders normally', async () => {
    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
    });

    await validateTargetHelper('https://mitacsc.ac.in/');

    expect(screen.getByText(/PASS \(Metadata \/ SSRF Blocked\)/i)).toBeDefined();
    expect(screen.getByText(/REQUIRED \(Central Transport\)/i)).toBeDefined();
  });

  // Test 10: Assessment Configuration renders normally
  it('10. Assessment Configuration renders normally', async () => {
    render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByText(/Assessment Configuration/i)).toBeDefined();
      expect(screen.getByDisplayValue(/CONTROLLED \(Operator Controlled Environment\)/i)).toBeDefined();
      expect(screen.getByDisplayValue(/SAFE_SCAN \(Safe & Non-Destructive\)/i)).toBeDefined();
    });
  });

  // Test 11: Literal "svg" is NOT rendered by the affected UI
  it('11. Literal "svg" is NOT rendered by the affected UI', async () => {
    const { container } = render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
    });

    await validateTargetHelper('https://mitacsc.ac.in/');

    // Check all text nodes in the rendered DOM: None should contain literal "svg" prefix
    const text = container.textContent || '';
    expect(text).not.toMatch(/svgAuthorized Scope Rules/i);
    expect(text).not.toMatch(/svg\[https:\/\/mitacsc\.ac\.in\/\]/i);
    expect(text).not.toMatch(/svg● SCOPE VALIDATED/i);

    // Verify all svg icons have aria-hidden="true"
    const svgs = container.querySelectorAll('svg');
    expect(svgs.length).toBeGreaterThan(0);
    svgs.forEach((svg) => {
      expect(svg.getAttribute('aria-hidden')).toBe('true');
    });
  });

  // Test 12: Full configuration page does not become blank after scope validation
  it('12. Full configuration page does not become blank after scope validation', async () => {
    const { container } = render(
      <ToastProvider>
        <NewAssessment />
      </ToastProvider>
    );

    await waitFor(() => {
      expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
    });

    await validateTargetHelper('https://mitacsc.ac.in/');

    // Page must contain all 4 primary sections and not be blank
    expect(screen.getByRole('heading', { name: /Target URL & Scope Program/i })).toBeDefined();
    expect(screen.getByRole('heading', { name: /Operator Authorization Gating/i })).toBeDefined();
    expect(screen.getByRole('heading', { name: /Assessment Configuration/i })).toBeDefined();
    expect(screen.getByRole('heading', { name: /PRE-FLIGHT READINESS/i })).toBeDefined();
    expect(screen.getByRole('button', { name: /Launch Controlled Assessment/i })).toBeDefined();
    expect(container.innerHTML.length).toBeGreaterThan(500);
  });

  // Assessment Configuration Controls Interactive Tests
  describe('Assessment Configuration Control Variations', () => {
    it('handles Assessment Mode changes between CONTROLLED and PRODUCTION_AUTHORIZED', async () => {
      render(
        <ToastProvider>
          <NewAssessment />
        </ToastProvider>
      );

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
      });

      // Switch to PRODUCTION_AUTHORIZED
      const modeSelect = screen.getByDisplayValue(/CONTROLLED \(Operator Controlled Environment\)/i);
      fireEvent.change(modeSelect, { target: { value: 'PRODUCTION_AUTHORIZED' } });

      expect(screen.getByText(/CONSERVATIVE PRODUCTION PROFILE \(LOCKED BY SERVER\)/i)).toBeDefined();
      expect(screen.getByText(/10 Max Requests/i)).toBeDefined();
      expect(screen.getByText(/1 Worker/i)).toBeDefined();
      expect(screen.getByText(/2 RPS/i)).toBeDefined();
      expect(screen.getByText(/GET\/HEAD\/OPTIONS/i)).toBeDefined();

      // Switch back to CONTROLLED
      const modeSelectProd = screen.getByDisplayValue(/PRODUCTION_AUTHORIZED \(Conservative Bug-Bounty Limits\)/i);
      fireEvent.change(modeSelectProd, { target: { value: 'CONTROLLED' } });

      expect(screen.getByText(/Controlled mode allows custom concurrency and budget allocations/i)).toBeDefined();
    });

    it('handles Scan Profile changes without crash', async () => {
      render(
        <ToastProvider>
          <NewAssessment />
        </ToastProvider>
      );

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
      });

      const profileSelect = screen.getByDisplayValue(/SAFE_SCAN \(Safe & Non-Destructive\)/i);
      fireEvent.change(profileSelect, { target: { value: 'PLAN_ONLY' } });
      expect(profileSelect.value).toBe('PLAN_ONLY');

      fireEvent.change(profileSelect, { target: { value: 'RECON_ONLY' } });
      expect(profileSelect.value).toBe('RECON_ONLY');

      fireEvent.change(profileSelect, { target: { value: 'FULL_AUTHORIZED_SCAN' } });
      expect(profileSelect.value).toBe('FULL_AUTHORIZED_SCAN');
    });

    it('handles custom budget and concurrency numeric input changes', async () => {
      render(
        <ToastProvider>
          <NewAssessment />
        </ToastProvider>
      );

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
      });

      // Find budget inputs
      const campaignBudgetInput = screen.getByLabelText(/Campaign Budget/i);
      fireEvent.change(campaignBudgetInput, { target: { value: '1000' } });
      expect(campaignBudgetInput.value).toBe('1000');

      const targetBudgetInput = screen.getByLabelText(/Per-Target Budget/i);
      fireEvent.change(targetBudgetInput, { target: { value: '250' } });
      expect(targetBudgetInput.value).toBe('250');

      const checkBudgetInput = screen.getByLabelText(/Per-Check Budget/i);
      fireEvent.change(checkBudgetInput, { target: { value: '50' } });
      expect(checkBudgetInput.value).toBe('50');

      const concurrencyInput = screen.getByLabelText(/Max Concurrency/i);
      fireEvent.change(concurrencyInput, { target: { value: '10' } });
      expect(concurrencyInput.value).toBe('10');
    });

    it('handles empty or zero numeric inputs gracefully without crashing', async () => {
      render(
        <ToastProvider>
          <NewAssessment />
        </ToastProvider>
      );

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /mit2\+/i })).toBeDefined();
      });

      const campaignBudgetInput = screen.getByLabelText(/Campaign Budget/i);
      // Empty input
      fireEvent.change(campaignBudgetInput, { target: { value: '' } });
      expect(campaignBudgetInput.value).toBe('1'); // clamped to safe min 1

      const concurrencyInput = screen.getByLabelText(/Max Concurrency/i);
      // Over-max input
      fireEvent.change(concurrencyInput, { target: { value: '50' } });
      expect(concurrencyInput.value).toBe('20'); // clamped to safe max 20
    });
  });

  // Normalizer Unit Tests
  describe('Helper Normalizer Functions', () => {
    it('normalizes scope rules from various backend shapes', () => {
      expect(normalizeScopeRules(null)).toEqual([]);
      expect(normalizeScopeRules({ in_scope_assets: ['https://example.com'] })).toEqual([
        'https://example.com',
      ]);
      expect(normalizeScopeRules({ in_scope_assets: '["https://example.com"]' })).toEqual([
        'https://example.com',
      ]);
      expect(
        normalizeScopeRules({
          in_scope_assets: [{ raw_scope_definition: 'https://example.com' }],
        })
      ).toEqual(['https://example.com']);
    });

    it('normalizes matched_rule safely', () => {
      expect(normalizeMatchedRule(null)).toBeNull();
      expect(normalizeMatchedRule('https://example.com')).toBe('https://example.com');
      expect(normalizeMatchedRule({ pattern: '*.example.com' })).toBe('*.example.com');
    });

    it('normalizes reason safely', () => {
      expect(normalizeReason(null)).toBe('Target validated against authorized scope.');
      expect(normalizeReason('Custom reason')).toBe('Custom reason');
      expect(normalizeReason({ message: 'Structured message' })).toBe('Structured message');
    });
  });
});
