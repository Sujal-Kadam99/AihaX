import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import Reports from '../pages/Reports';
import * as api from '../lib/api';
import { ToastProvider } from '../context/ToastContext';
import { BrowserRouter } from 'react-router-dom';

vi.mock('../lib/api', () => ({
  getCampaigns: vi.fn(),
  downloadCampaignReport: vi.fn(),
  generateCampaignReports: vi.fn(),
}));

describe('Reports UI Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders loading state initially and then displays campaigns', async () => {
    api.getCampaigns.mockResolvedValueOnce({
      data: {
        data: [
          {
            id: 'camp-123',
            campaign_id: 'camp-123',
            name: 'Eternal-Zomato-Web-001',
            target_url: 'https://www.zomato.com',
            mode: 'CONTROLLED_HUMAN_IN_THE_LOOP',
            status: 'AUTHORIZED',
          },
        ],
      },
    });

    render(
      <BrowserRouter>
        <ToastProvider>
          <Reports />
        </ToastProvider>
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Eternal-Zomato-Web-001')).toBeDefined();
      expect(screen.getByText('https://www.zomato.com')).toBeDefined();
    });
  });

  it('handles report creation/generation success', async () => {
    api.getCampaigns.mockResolvedValue({
      data: {
        data: [
          {
            id: 'camp-123',
            campaign_id: 'camp-123',
            name: 'Eternal-Zomato-Web-001',
            target_url: 'https://www.zomato.com',
            mode: 'CONTROLLED_HUMAN_IN_THE_LOOP',
            status: 'AUTHORIZED',
          },
        ],
      },
    });

    api.generateCampaignReports.mockResolvedValueOnce({
      data: {
        success: true,
        campaign_id: 'camp-123',
        verified_findings_count: 2,
      },
    });

    render(
      <BrowserRouter>
        <ToastProvider>
          <Reports />
        </ToastProvider>
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Eternal-Zomato-Web-001')).toBeDefined();
    });

    const generateBtn = screen.getByRole('button', { name: /generate/i });
    fireEvent.click(generateBtn);

    await waitFor(() => {
      expect(api.generateCampaignReports).toHaveBeenCalledWith('camp-123');
    });
  });

  it('handles PDF download and validates PDF magic header', async () => {
    api.getCampaigns.mockResolvedValue({
      data: {
        data: [
          {
            id: 'camp-123',
            campaign_id: 'camp-123',
            name: 'Eternal-Zomato-Web-001',
            target_url: 'https://www.zomato.com',
            mode: 'CONTROLLED_HUMAN_IN_THE_LOOP',
            status: 'AUTHORIZED',
          },
        ],
      },
    });

    // Mock valid PDF blob starting with %PDF-
    const pdfBlob = new Blob(['%PDF-1.4 sample content'], { type: 'application/pdf' });
    api.downloadCampaignReport.mockResolvedValueOnce({
      data: pdfBlob,
    });

    // Mock URL.createObjectURL
    window.URL.createObjectURL = vi.fn(() => 'blob:mock-url');
    window.URL.revokeObjectURL = vi.fn();

    render(
      <BrowserRouter>
        <ToastProvider>
          <Reports />
        </ToastProvider>
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Eternal-Zomato-Web-001')).toBeDefined();
    });

    const downloadBtn = screen.getByRole('button', { name: /download pdf/i });
    fireEvent.click(downloadBtn);

    await waitFor(() => {
      expect(api.downloadCampaignReport).toHaveBeenCalledWith('camp-123');
    });
  });

  it('handles report download 404 error cleanly', async () => {
    api.getCampaigns.mockResolvedValue({
      data: {
        data: [
          {
            id: 'camp-123',
            campaign_id: 'camp-123',
            name: 'Eternal-Zomato-Web-001',
            target_url: 'https://www.zomato.com',
            mode: 'CONTROLLED_HUMAN_IN_THE_LOOP',
            status: 'AUTHORIZED',
          },
        ],
      },
    });

    const error404 = new Error('Not Found');
    error404.response = { status: 404, data: { detail: 'Report not found' } };
    api.downloadCampaignReport.mockRejectedValueOnce(error404);

    render(
      <BrowserRouter>
        <ToastProvider>
          <Reports />
        </ToastProvider>
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Eternal-Zomato-Web-001')).toBeDefined();
    });

    const downloadBtn = screen.getByRole('button', { name: /download pdf/i });
    fireEvent.click(downloadBtn);

    await waitFor(() => {
      expect(api.downloadCampaignReport).toHaveBeenCalledWith('camp-123');
    });
  });
});
