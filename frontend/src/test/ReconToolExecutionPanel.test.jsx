import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import ReconToolExecutionPanel, { TOOL_STATUS_MAP } from '../components/ReconToolExecutionPanel';

describe('ReconToolExecutionPanel UI Component', () => {
  const mockValidationResult = {
    target: 'https://www.mitacsc.ac.in',
    host: 'www.mitacsc.ac.in',
    base_domain: 'mitacsc.ac.in',
    campaign_id: 'phase25-camp',
    authorization_record_id: 'auth-123',
    suite_status: 'VALIDATION_COMPLETE',
    tool_records: {
      subfinder: {
        tool_name: 'subfinder',
        status: 'EXECUTION_FAILED',
        exit_code: null,
        parsed_result_count: 0,
        snapshot_contribution_count: 0,
        evidence_id: null,
        failure_reason: 'Executable subfinder not found on system PATH.',
        arguments: ['-d', 'mitacsc.ac.in', '-silent'],
      },
      sublist3r: {
        tool_name: 'sublist3r',
        status: 'NOT_IMPLEMENTED',
        exit_code: null,
        parsed_result_count: 0,
        snapshot_contribution_count: 0,
        evidence_id: null,
        failure_reason: 'Sublist3r is not part of the current AihaX recon implementation and was intentionally not executed.',
        arguments: [],
      },
      crtsh: {
        tool_name: 'crtsh',
        status: 'LIVE_VALIDATED',
        exit_code: 0,
        parsed_result_count: 14,
        snapshot_contribution_count: 12,
        evidence_id: 'sha256-crt-hash-xyz',
        failure_reason: null,
        arguments: ['https://crt.sh/?q=%.mitacsc.ac.in&output=json'],
      },
      dns_recon: {
        tool_name: 'dns_recon',
        status: 'LIVE_VALIDATED',
        exit_code: 0,
        parsed_result_count: 5,
        snapshot_contribution_count: 5,
        evidence_id: 'sha256-dns-hash-xyz',
        failure_reason: null,
        arguments: ['record_types=A,AAAA,CNAME,MX,NS,TXT,SOA'],
      },
      http_probe: {
        tool_name: 'http_probe',
        status: 'LIVE_VALIDATED',
        exit_code: 0,
        parsed_result_count: 1,
        snapshot_contribution_count: 1,
        evidence_id: 'sha256-http-hash-xyz',
        failure_reason: null,
        arguments: ['GET', 'https://www.mitacsc.ac.in'],
      },
      nmap: {
        tool_name: 'nmap',
        status: 'BLOCKED_POLICY',
        exit_code: null,
        parsed_result_count: 0,
        snapshot_contribution_count: 0,
        evidence_id: null,
        failure_reason: 'Port scanning is not explicitly authorized under program policy.',
        arguments: ['-sT', '-T4', '--open', 'mitacsc.ac.in'],
      },
      nuclei: {
        tool_name: 'nuclei',
        status: 'NOT_SELECTED_RECON_ONLY',
        exit_code: null,
        parsed_result_count: 0,
        snapshot_contribution_count: 0,
        evidence_id: null,
        failure_reason: 'Nuclei is a vulnerability scanner; excluded from recon-only gate.',
        arguments: [],
      },
    },
  };

  it('renders all table headers and tools correctly', () => {
    render(<ReconToolExecutionPanel validationResult={mockValidationResult} />);

    expect(screen.getByText('Reconnaissance Tool Execution & Validation Gate')).toBeDefined();
    expect(screen.getByText('https://www.mitacsc.ac.in')).toBeDefined();

    // Check specific tools
    expect(screen.getByText('subfinder')).toBeDefined();
    expect(screen.getByText('sublist3r')).toBeDefined();
    expect(screen.getByText('crtsh')).toBeDefined();
    expect(screen.getByText('dns_recon')).toBeDefined();
    expect(screen.getByText('http_probe')).toBeDefined();
    expect(screen.getByText('nmap')).toBeDefined();
    expect(screen.getByText('nuclei')).toBeDefined();
  });

  it('displays accurate statuses for live validated, not implemented, and failed tools', () => {
    render(<ReconToolExecutionPanel validationResult={mockValidationResult} />);

    // Live validated tools
    const liveBadges = screen.getAllByText('LIVE VALIDATED');
    expect(liveBadges.length).toBeGreaterThanOrEqual(3);

    // Not implemented for sublist3r
    expect(screen.getByText('NOT IMPLEMENTED')).toBeDefined();

    // Execution failed for subfinder
    expect(screen.getByText('EXECUTION FAILED')).toBeDefined();

    // Blocked policy for nmap
    expect(screen.getByText('BLOCKED POLICY')).toBeDefined();
  });

  it('expands tool details when clicked to show arguments and failure reason', () => {
    render(<ReconToolExecutionPanel validationResult={mockValidationResult} />);

    // Click sublist3r row
    const sublist3rRow = screen.getByText('sublist3r');
    fireEvent.click(sublist3rRow);

    // Rationale should be visible
    expect(screen.getByText(/Sublist3r is not part of the current AihaX recon implementation/)).toBeDefined();

    // Click subfinder row
    const subfinderRow = screen.getByText('subfinder');
    fireEvent.click(subfinderRow);

    expect(screen.getByText(/Executable subfinder not found on system PATH/)).toBeDefined();
  });

  it('filters tools by EXECUTED, BLOCKED, and FAILED tabs', () => {
    render(<ReconToolExecutionPanel validationResult={mockValidationResult} />);

    // Click EXECUTED filter
    fireEvent.click(screen.getByRole('button', { name: 'EXECUTED' }));
    expect(screen.getByText('crtsh')).toBeDefined();
    expect(screen.queryByText('sublist3r')).toBeNull();

    // Click BLOCKED filter
    fireEvent.click(screen.getByRole('button', { name: 'BLOCKED' }));
    expect(screen.getByText('sublist3r')).toBeDefined();
    expect(screen.getByText('nmap')).toBeDefined();
    expect(screen.queryByText('crtsh')).toBeNull();

    // Click FAILED filter
    fireEvent.click(screen.getByRole('button', { name: 'FAILED' }));
    expect(screen.getByText('subfinder')).toBeDefined();
    expect(screen.queryByText('crtsh')).toBeNull();
  });

  it('shows the hostname on per-host follow-up recon records', () => {
    const result = {
      ...mockValidationResult,
      tool_records: {
        'http_probe:app.example.com': {
          tool_name: 'http_probe',
          target: 'https://app.example.com',
          status: 'LIVE_VALIDATED',
          exit_code: 0,
          parsed_result_count: 1,
        },
      },
    };

    render(<ReconToolExecutionPanel validationResult={result} />);

    expect(screen.getByText(/http_probe.*app\.example\.com/)).toBeDefined();
  });
});


it('shows discovered, followed-up, and deferred host coverage', () => {
  render(<ReconToolExecutionPanel validationResult={{
    target: 'https://example.test',
    tool_records: {},
    host_followup_summary: {
      in_scope_hosts_discovered: 12,
      hosts_followed_up: 10,
      hosts_deferred_by_budget: 2,
      followup_host_limit: 10,
    },
  }} />);

  expect(screen.getByText(/12 in-scope hosts discovered/)).toBeDefined();
  expect(screen.getByText(/10 followed up/)).toBeDefined();
  expect(screen.getByText(/2 deferred by the host budget/)).toBeDefined();
});


it('shows the authorized Nmap port selection in run results', () => {
  render(<ReconToolExecutionPanel validationResult={{
    target: 'https://example.test',
    tool_records: {},
    port_scan_coverage: {
      profile: 'all_authorized',
      allowed_ports: '80,8000-8100',
      excluded_ports: '443',
      selected_ports: '80,8000-8100',
      selected_port_count: 102,
    },
  }} />);

  expect(screen.getByText(/Nmap port plan: all authorized TCP ports/)).toBeDefined();
  expect(screen.getByText(/Selected ports: 80,8000-8100 \(102\)/)).toBeDefined();
});
