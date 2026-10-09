import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import LiveReconPreflightModal from '../components/LiveReconPreflightModal';

describe('LiveReconPreflightModal service scan scope', () => {
  it('offers explicit port coverage profiles and shows program port bounds', () => {
    render(<LiveReconPreflightModal
      isOpen
      campaignId="campaign"
      preflightData={{
        can_launch: false,
        target: 'https://example.test',
        campaign_name: 'Example',
        authorization: {},
        scope: { allowed_ports: [80, 443, 8443], excluded_ports: [443] },
        safety_budget: {},
        tool_matrix: [],
      }}
      onClose={() => {}}
      onConfirmLaunch={() => {}}
    />);

    fireEvent.click(screen.getByRole('checkbox', { name: /Bounded service discovery/ }));

    expect(screen.getByRole('option', { name: /Common web ports within scope/ })).toBeDefined();
    expect(screen.getByRole('option', { name: /All authorized TCP ports/ })).toBeDefined();
    expect(screen.getByText(/Allowed: 80, 443, 8443 · Excluded: 443/)).toBeDefined();
  });
});


