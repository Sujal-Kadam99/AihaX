import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000',
  timeout: 30000,
});

let tokenPromise = null;

async function ensureToken() {
  if (api.defaults.headers.common['X-AihaX-Token']) return;
  if (!tokenPromise) {
    tokenPromise = axios
      .get('http://localhost:8000/api/auth/token')
      .then((res) => {
        api.defaults.headers.common['X-AihaX-Token'] = res.data.token;
      })
      .catch((err) => {
        tokenPromise = null;
        throw err;
      });
  }
  await tokenPromise;
}

api.interceptors.request.use(async (config) => {
  if (!config.url?.includes('/api/auth/token') && !config.url?.includes('/api/health')) {
    await ensureToken();
    const token = api.defaults.headers.common['X-AihaX-Token'];
    if (token) {
      if (config.headers && typeof config.headers.set === 'function') {
        config.headers.set('X-AihaX-Token', token);
      } else {
        config.headers['X-AihaX-Token'] = token;
      }
    }
  }
  return config;
});

export async function getApiToken() {
  await ensureToken();
  return api.defaults.headers.common['X-AihaX-Token'];
}

// ─────────────────────────────────────────────────────────────────────────────
// Campaign Operations (Phase 8 Production Operations)
// ─────────────────────────────────────────────────────────────────────────────
export const createCampaign = (payload) => api.post('/api/campaigns', payload);
export const getCampaigns = (params) => api.get('/api/campaigns', { params });
export const getCampaign = (id) => api.get(`/api/campaigns/${id}`);
export const authorizeCampaign = (id, payload) => api.post(`/api/campaigns/${id}/authorize`, payload);
export const startCampaign = (id) => api.post(`/api/campaigns/${id}/start`);
export const pauseCampaign = (id) => api.post(`/api/campaigns/${id}/pause`);
export const resumeCampaign = (id) => api.post(`/api/campaigns/${id}/resume`);
export const cancelCampaign = (id) => api.post(`/api/campaigns/${id}/cancel`);
export const getCampaignStatus = (id) => api.get(`/api/campaigns/${id}/status`);
export const getCampaignPreflight = (id) => api.get(`/api/campaigns/${id}/preflight`);
export const getCampaignRuntime = (id, params) => api.get(`/api/campaigns/${id}/runtime`, { params });
export const getCampaignReconDiagnostics = (id) => api.get(`/api/campaigns/${id}/recon-diagnostics`);
export const getCampaignFindings = (id, params) => api.get(`/api/campaigns/${id}/findings`, { params });
export const getCampaignCoverage = (id) => api.get(`/api/campaigns/${id}/coverage`);
// ─────────────────────────────────────────────────────────────────────────────
// Phase 20: Hunting Intelligence & Operator Queue
// ─────────────────────────────────────────────────────────────────────────────
export const getCampaignHuntingRecommendations = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/hunting/recommendations`);
export const logHuntingDecision = (campaignId, payload) =>
  api.post(`/api/campaigns/${campaignId}/hunting/decision`, payload);
export const getCampaignSurfaceInventory = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/hunting/surface`);
export const getCampaignNegativeEvidence = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/hunting/negative-evidence`);

export const getCampaignEvidence = (id, params) => api.get(`/api/campaigns/${id}/evidence`, { params });
export const getEvidenceDetail = (id, evidenceId) => api.get(`/api/campaigns/${id}/evidence/${evidenceId}`);
export const getCampaignExecutionSummary = (id) => api.get(`/api/campaigns/${id}/execution-summary`);
export const getCampaignTimeline = (id, params) => api.get(`/api/campaigns/${id}/timeline`, { params });
export const getCampaignAuditTrail = (id) => api.get(`/api/campaigns/${id}/audit`);
export const verifyCampaignIntegrity = (id) => api.get(`/api/campaigns/${id}/integrity`);
export const generateCampaignReports = (id) => api.post(`/api/campaigns/${id}/reports`);
export const getOperationalMetrics = () => api.get('/api/campaigns/metrics/operational');

// ─────────────────────────────────────────────────────────────────────────────
// Legacy Scans (Backward Compatibility)
// ─────────────────────────────────────────────────────────────────────────────
export const startScan = (config) => api.post('/api/scan/start', config);
export const getScan = (scanId) => api.get(`/api/scan/${scanId}`);
export const cancelScan = (scanId) => api.delete(`/api/scan/${scanId}`);
export const getScanHistory = () => api.get('/api/scan/history/list');

// ─────────────────────────────────────────────────────────────────────────────
// Findings & Reports
// ─────────────────────────────────────────────────────────────────────────────
export const getFindings = (scanId, severity) =>
  api.get(`/api/findings/${scanId}`, { params: { severity } });
export const getFindingDetail = (findingId) => api.get(`/api/findings/detail/${findingId}`);
export const getPendingReviewFindings = (scanId) => api.get(`/api/findings/pending-review/${scanId}`);
export const reviewFinding = (findingId, payload) => api.post(`/api/findings/${findingId}/review`, payload);
export const bindCampaignTarget = (campaignId, payload) => api.post(`/api/campaigns/${campaignId}/target`, payload);
export const killCampaign = (campaignId, payload) => api.post(`/api/campaigns/${campaignId}/kill`, payload);
export const downloadReport = (id) =>
  api.get(`/api/reports/scan/${id}`, { responseType: 'blob' });
export const downloadCampaignReport = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/reports/download`, { responseType: 'blob' });

// ─────────────────────────────────────────────────────────────────────────────
// Programs & Scope Management
// ─────────────────────────────────────────────────────────────────────────────
export const getPrograms = () => api.get('/api/programs');
export const getProgram = (id) => api.get(`/api/programs/${id}`);
export const createProgram = (payload) => api.post('/api/programs', payload);
export const updateProgramScope = (id, scope) => api.put(`/api/programs/${id}/scope`, scope);
export const validateTargetScope = (id, target, port) =>
  api.post(`/api/programs/${id}/validate-target`, { target, port });

// ─────────────────────────────────────────────────────────────────────────────
// Watch Mode, Settings & Health
// ─────────────────────────────────────────────────────────────────────────────
export const createWatchSchedule = (payload) => api.post('/api/watch', payload);
export const getWatchSchedules = () => api.get('/api/watch/list');
export const deleteWatchSchedule = (scheduleId) => api.delete(`/api/watch/${scheduleId}`);
export const saveSettings = (settings) => api.post('/api/settings', settings);
export const getSettings = () => api.get('/api/settings');
export const healthCheck = () => api.get('/api/health');
export const getEntitlements = () => api.get('/api/entitlements');
export const getUserProfile = () => api.get('/api/auth/me');
export const createCheckoutSession = (payload) => api.post('/api/billing/checkout', payload);
export const getBillingPlans = () => api.get('/api/billing/plans');
export const createCustomerPortalSession = () => api.post('/api/billing/portal');

// ─────────────────────────────────────────────────────────────────────────────
// Phase 21 & 22: Controlled & Real-World Validation
// ─────────────────────────────────────────────────────────────────────────────
export const getCampaignHypotheses = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/hypotheses`);
export const logHypothesisDecision = (campaignId, hypothesisId, payload) =>
  api.post(`/api/campaigns/${campaignId}/hypotheses/${hypothesisId}/decision`, payload);
export const executeVerification = (campaignId, hypothesisId, payload) =>
  api.post(`/api/campaigns/${campaignId}/hypotheses/${hypothesisId}/verify`, payload);
export const getCampaignVerifications = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/verifications`);
export const getVerificationRun = (campaignId, verificationId) =>
  api.get(`/api/campaigns/${campaignId}/verifications/${verificationId}`);
export const getCampaignVerificationBudget = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/verification-budget`);

export const getRealVerifications = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/real-verifications`);
export const getRealVerificationRun = (campaignId, runId) =>
  api.get(`/api/campaigns/${campaignId}/real-verifications/${runId}`);
export const approveRealVerification = (campaignId, hypothesisId, payload) =>
  api.post(`/api/campaigns/${campaignId}/real-verifications/${hypothesisId}/approve`, payload);
export const executeRealVerification = (campaignId, hypothesisId, payload) =>
  api.post(`/api/campaigns/${campaignId}/real-verifications/${hypothesisId}/execute`, payload);
export const getRealEvidenceChains = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/real-evidence-chains`);
export const getRealAuditTrail = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/real-audit-trail`);

// ─────────────────────────────────────────────────────────────────────────────
// Phase 23: Advanced Authorized Vulnerability Research & Multi-Step Validation
// ─────────────────────────────────────────────────────────────────────────────
export const getAttackSurface = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/attack-surface`);
export const getCorrelatedHypotheses = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/hypotheses/correlated`);
export const getValidationPlans = (campaignId) =>
  api.get(`/api/campaigns/${campaignId}/validation-plans`);
export const getValidationPlanById = (campaignId, planId) =>
  api.get(`/api/campaigns/${campaignId}/validation-plans/${planId}`);
export const approveValidationPlan = (campaignId, planId, payload) =>
  api.post(`/api/campaigns/${campaignId}/validation-plans/${planId}/approve`, payload);
export const executeValidationPlan = (campaignId, planId, payload) =>
  api.post(`/api/campaigns/${campaignId}/validation-plans/${planId}/execute`, payload);
export const stopValidationPlan = (campaignId, planId, payload) =>
  api.post(`/api/campaigns/${campaignId}/validation-plans/${planId}/stop`, payload);
export const reproduceValidationPlan = (campaignId, planId, payload) =>
  api.post(`/api/campaigns/${campaignId}/validation-plans/${planId}/reproduce`, payload);
export const getValidationPlanObservations = (campaignId, planId) =>
  api.get(`/api/campaigns/${campaignId}/validation-plans/${planId}/observations`);
export const getValidationPlanEvidenceChain = (campaignId, planId) =>
  api.get(`/api/campaigns/${campaignId}/validation-plans/${planId}/evidence-chain`);
export const getFindingConfidence = (campaignId, findingId) =>
  api.get(`/api/campaigns/${campaignId}/findings/${findingId}/confidence`);

export const getCampaignReconLivePreflight = (id) => 
  api.get(`/api/campaigns/${id}/recon-live-preflight`);
export const postCampaignReconLiveValidation = (id, mode, payload) => 
  api.post(`/api/campaigns/${id}/recon-live-validation?mode=${mode}`, payload);

export { api };
export default api;


