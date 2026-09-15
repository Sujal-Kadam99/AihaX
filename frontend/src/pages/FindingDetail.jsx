import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  Lock,
  ShieldCheck,
  XCircle,
  RefreshCw,
  UserCheck,
  ShieldAlert,
  HelpCircle,
  Activity,
  FileCheck,
} from 'lucide-react';
import { getFindingDetail, reviewFinding } from '../lib/api';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';

export default function FindingDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [reviewNotes, setReviewNotes] = useState('');
  const [reviewLoading, setReviewLoading] = useState(false);
  const [reviewFeedback, setReviewFeedback] = useState(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const res = await getFindingDetail(id);
        setFinding(res.data?.data || res.data);
      } catch (err) {
        setError(err.response?.data?.detail || 'Finding not found.');
      } finally {
        setLoading(false);
      }
    }
    if (id) load();
  }, [id]);

  const handleReview = async (decision) => {
    try {
      setReviewLoading(true);
      setReviewFeedback(null);
      const res = await reviewFinding(id, {
        decision,
        notes: reviewNotes,
        actor: 'operator',
      });
      if (res.data?.success) {
        setReviewFeedback({ type: 'success', message: `Finding ${decision}ed successfully.` });
        const updated = await getFindingDetail(id);
        setFinding(updated.data?.data || updated.data);
      }
    } catch (err) {
      setReviewFeedback({
        type: 'error',
        message: err.response?.data?.detail || `Failed to ${decision.toLowerCase()} finding.`,
      });
    } finally {
      setReviewLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="p-8 text-center text-xs text-text-secondary">
        Loading finding evidence and verification graph...
      </div>
    );
  }

  if (error || !finding) {
    return (
      <Card className="p-8 text-center bg-surface border-border space-y-3 max-w-lg mx-auto mt-12">
        <AlertTriangle className="w-8 h-8 mx-auto text-amber-400" />
        <h2 className="text-sm font-bold text-text-primary">Unable to load finding</h2>
        <p className="text-xs text-text-secondary">{error || 'Finding record does not exist.'}</p>
        <Button variant="secondary" size="sm" onClick={() => navigate('/findings')}>
          Back to Findings
        </Button>
      </Card>
    );
  }

  const isVerified = finding.verification_status === 'VERIFIED' || finding.verdict === 'Verified';

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Back button */}
      <div>
        <Button
          variant="ghost"
          size="xs"
          onClick={() => navigate(-1)}
          className="flex items-center gap-1.5 text-text-secondary hover:text-text-primary"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back
        </Button>
      </div>

      {/* Header Banner */}
      <Card className="p-5 bg-surface border-border space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 pb-3 border-b border-border">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge variant="danger" size="sm">
                {finding.severity?.toUpperCase() || 'HIGH'}
              </Badge>
              <Badge variant={isVerified ? 'success' : 'warning'} size="sm">
                {finding.verification_status || finding.verdict}
              </Badge>
              <span className="text-xs font-mono text-text-muted">ID: {finding.id}</span>
            </div>
            <h1 className="text-lg font-bold text-text-primary">{finding.title}</h1>
            <div className="text-xs font-mono text-text-secondary">
              Target: <span className="text-accent">{finding.affected_url}</span>
              {finding.affected_param && (
                <span className="ml-2">
                  &bull; Parameter: <code className="text-amber-400">{finding.affected_param}</code>
                </span>
              )}
            </div>
          </div>

          <div className="text-right flex-shrink-0">
            <div className="text-xs font-mono text-text-muted">Confidence Score</div>
            <div className="text-2xl font-bold font-mono text-text-primary mt-0.5">
              {finding.confidence || 0}%
            </div>
          </div>
        </div>

        {/* Verification Status Banner */}
        <div
          className={`p-3.5 rounded border text-xs flex items-center justify-between ${
            isVerified
              ? 'bg-emerald-950/30 border-emerald-800 text-emerald-300'
              : 'bg-amber-950/30 border-amber-800 text-amber-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {isVerified ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
            )}
            <div>
              <span className="font-bold">
                {isVerified ? 'Mathematically Verified Vulnerability' : 'Unverified Candidate Finding'}
              </span>
              <div className="text-[11px] opacity-80 mt-0.5">
                {isVerified
                  ? 'Confirmed via safe deterministic baseline differential verification.'
                  : 'Observation pending automated reproduction or authorization gating.'}
              </div>
            </div>
          </div>
          {finding.cwe_id && (
            <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-surface-2 text-text-primary border border-border">
              {finding.cwe_id}
            </span>
          )}
        </div>
      </Card>

      {/* Summary & Impact */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="p-4 bg-surface border-border space-y-2">
          <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
            Vulnerability Summary
          </h2>
          <p className="text-xs text-text-secondary leading-relaxed">
            {finding.summary || finding.remediation?.summary || 'Observed anomalous behavior during check execution.'}
          </p>
        </Card>

        <Card className="p-4 bg-surface border-border space-y-3">
          <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
            Impact Analysis (Factual vs Theoretical)
          </h2>
          <div className="space-y-2 text-xs">
            <div>
              <span className="font-bold text-emerald-400 font-mono text-[10px] uppercase block">Confirmed Impact (Observed Fact)</span>
              <p className="text-text-secondary mt-0.5">
                {finding.impact_confirmed || 'Demonstrated security condition evidenced by verified HTTP response.'}
              </p>
            </div>
            <div>
              <span className="font-bold text-amber-400 font-mono text-[10px] uppercase block">Potential Impact [INFERENCE]</span>
              <p className="text-text-secondary mt-0.5">
                {finding.impact_potential?.startsWith('[INFERENCE]')
                  ? finding.impact_potential
                  : `[INFERENCE] ${finding.impact_potential || 'Potential unauthorized access or state manipulation if defense-in-depth controls fail.'}`}
              </p>
            </div>
          </div>
        </Card>
      </div>

      {/* Evidence & HTTP Proof (Secret Redacted) */}
      <Card className="p-5 bg-surface border-border space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-border">
          <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider flex items-center gap-2">
            <Terminal className="w-4 h-4 text-accent" />
            Cryptographic Evidence & Proof of Concept
          </h2>
          <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
            <Lock className="w-3 h-3" /> Secrets Redacted Before Persistence
          </div>
        </div>

        {finding.proof_request && (
          <div className="space-y-1.5">
            <div className="text-xs font-medium text-text-secondary">Proof Request:</div>
            <pre className="p-3 rounded bg-surface-2 border border-border text-[11px] font-mono text-text-primary overflow-x-auto whitespace-pre-wrap">
              {finding.proof_request}
            </pre>
          </div>
        )}

        {finding.proof_response && (
          <div className="space-y-1.5">
            <div className="text-xs font-medium text-text-secondary">Proof Response:</div>
            <pre className="p-3 rounded bg-surface-2 border border-border text-[11px] font-mono text-text-primary overflow-x-auto whitespace-pre-wrap max-h-60 overflow-y-auto">
              {finding.proof_response}
            </pre>
          </div>
        )}
      </Card>

      {/* Deterministic Verification Graph Analysis */}
      <Card className="p-5 bg-surface border-border space-y-3">
        <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider pb-2 border-b border-border">
          Deterministic Verification Audit
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-2.5 rounded bg-surface-2 border border-border">
            <span className="text-text-muted text-[10px] uppercase font-semibold">Method</span>
            <div className="font-mono text-[11px] text-text-primary mt-0.5">
              {finding.verification_method || 'Deterministic Contract'}
            </div>
          </div>
          <div className="p-2.5 rounded bg-surface-2 border border-border">
            <span className="text-text-muted text-[10px] uppercase font-semibold">Reason Code</span>
            <div className="font-mono text-[11px] text-emerald-400 mt-0.5">
              {finding.verification_reason_code || 'REPRODUCED_SUCCESSFULLY'}
            </div>
          </div>
          <div className="p-2.5 rounded bg-surface-2 border border-border">
            <span className="text-text-muted text-[10px] uppercase font-semibold">Evidence IDs</span>
            <div className="font-mono text-[11px] text-text-secondary mt-0.5 truncate">
              {finding.evidence_ids || 'EVD-VALIDATED'}
            </div>
          </div>
          <div className="p-2.5 rounded bg-surface-2 border border-border">
            <span className="text-text-muted text-[10px] uppercase font-semibold">Timestamp</span>
            <div className="font-mono text-[11px] text-text-secondary mt-0.5">
              {finding.verification_timestamp || 'Active'}
            </div>
          </div>
        </div>
      </Card>

      {/* Automated Finding Verification & Evidence Quality Gate */}
      {(() => {
        const explanation = (() => {
          if (!finding.verification_explanation) return null;
          if (typeof finding.verification_explanation === 'object') return finding.verification_explanation;
          try {
            return JSON.parse(finding.verification_explanation);
          } catch {
            return { reason: String(finding.verification_explanation) };
          }
        })();

        const disp = (finding.finding_disposition || explanation?.disposition || finding.verification_status || 'INCONCLUSIVE').toUpperCase();
        const condConf = finding.condition_confidence ?? explanation?.condition_confidence ?? 0;
        const impConf = finding.impact_confidence ?? explanation?.impact_confidence ?? 0;
        const reproConf = finding.reproducibility_confidence ?? explanation?.reproducibility_confidence ?? 0;
        const expConf = finding.exploitability_confidence ?? explanation?.exploitability_confidence ?? 0;
        const polConf = finding.policy_eligibility_confidence ?? explanation?.policy_eligibility_confidence ?? 0;
        const bountyElig = (finding.bounty_eligibility || explanation?.bounty_eligibility || 'UNKNOWN').toUpperCase();

        const isError = disp === 'VERIFICATION_ERROR';
        const isValidated = disp === 'VALIDATED' || disp === 'EXPLOITABLE' || disp === 'VULNERABILITY';
        const isHardening = disp === 'HARDENING_ONLY';
        const isFP = disp === 'FALSE_POSITIVE';

        let dispColorClass = 'text-amber-400 bg-amber-950/20 border-amber-800';
        if (isValidated) {
          dispColorClass = 'text-emerald-300 bg-emerald-950/20 border-emerald-800';
        } else if (isHardening) {
          dispColorClass = 'text-blue-300 bg-blue-950/20 border-blue-800';
        } else if (isFP) {
          dispColorClass = 'text-rose-300 bg-rose-950/20 border-rose-800';
        } else if (isError) {
          dispColorClass = 'text-rose-400 bg-rose-950/40 border-rose-800';
        }

        return (
          <Card
            data-testid={isError ? 'verification-error-card' : 'automated-verification-gate-card'}
            className="p-5 bg-surface border-border space-y-4"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border">
              <div className="flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-accent" />
                <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                  Automated Finding Verification & Quality Gate
                </h2>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-text-muted">Machine Disposition:</span>
                <span className={`px-2.5 py-0.5 rounded text-[11px] font-bold font-mono border uppercase ${dispColorClass}`}>
                  {disp}
                </span>
                <span className="text-[11px] text-text-muted ml-2">Bounty Scope:</span>
                <Badge
                  variant={bountyElig === 'ELIGIBLE' ? 'success' : bountyElig === 'INELIGIBLE' ? 'danger' : 'secondary'}
                  size="xs"
                >
                  {bountyElig}
                </Badge>
              </div>
            </div>

            {/* Error banner if VERIFICATION_ERROR */}
            {isError && (
              <div
                data-testid="verification-error-banner"
                className="p-3.5 rounded bg-rose-950/40 border border-rose-800 text-rose-300 text-xs flex items-center gap-2"
              >
                <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
                <div>
                  <div className="font-bold">Automated Verification Failure</div>
                  <div className="text-[11px] opacity-90 mt-0.5">
                    {explanation?.reason || 'The verification engine encountered an internal processing error.'}
                  </div>
                </div>
              </div>
            )}

            {/* Machine Reason Explanation */}
            <div className="p-3.5 rounded bg-surface-2 border border-border space-y-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-accent font-mono block">
                Why AihaX Reached This Disposition
              </span>
              <p className="text-xs text-text-primary leading-relaxed">
                {explanation?.reason || finding.verification_reason_code || 'Deterministic automated finding verification evaluated stored cryptographic evidence, false-positive rules, baseline differential, and program scope eligibility.'}
              </p>
              {explanation?.failed_requirements && explanation.failed_requirements.length > 0 && (
                <div className="mt-2 pt-2 border-t border-border/50 text-[11px] text-rose-300 font-mono">
                  Unmet Requirements: {explanation.failed_requirements.join(', ')}
                </div>
              )}
            </div>

            {/* Multi-Dimensional Confidence Matrix */}
            <div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted font-mono block mb-2.5">
                Multi-Dimensional Confidence Breakdown
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 text-xs">
                <div className="p-2.5 rounded bg-surface-2 border border-border">
                  <span className="text-text-muted text-[10px] block">Condition Confidence</span>
                  <div className="font-mono font-bold text-text-primary text-sm mt-0.5">
                    {Math.round(condConf * 100)}%
                  </div>
                  <div className="text-[10px] text-text-muted mt-0.5">Anomaly observed</div>
                </div>
                <div className="p-2.5 rounded bg-surface-2 border border-border">
                  <span className="text-text-muted text-[10px] block">Impact Confidence</span>
                  <div className={`font-mono font-bold text-sm mt-0.5 ${impConf > 0.5 ? 'text-emerald-400' : 'text-text-secondary'}`}>
                    {Math.round(impConf * 100)}%
                  </div>
                  <div className="text-[10px] text-text-muted mt-0.5">Technical harm proven</div>
                </div>
                <div className="p-2.5 rounded bg-surface-2 border border-border">
                  <span className="text-text-muted text-[10px] block">Reproducibility</span>
                  <div className={`font-mono font-bold text-sm mt-0.5 ${reproConf > 0.5 ? 'text-emerald-400' : 'text-text-secondary'}`}>
                    {Math.round(reproConf * 100)}%
                  </div>
                  <div className="text-[10px] text-text-muted mt-0.5">Differential consistent</div>
                </div>
                <div className="p-2.5 rounded bg-surface-2 border border-border">
                  <span className="text-text-muted text-[10px] block">Exploitability</span>
                  <div className={`font-mono font-bold text-sm mt-0.5 ${expConf > 0.5 ? 'text-emerald-400' : 'text-text-secondary'}`}>
                    {Math.round(expConf * 100)}%
                  </div>
                  <div className="text-[10px] text-text-muted mt-0.5">Weaponization barrier</div>
                </div>
                <div className="p-2.5 rounded bg-surface-2 border border-border">
                  <span className="text-text-muted text-[10px] block">Policy Eligibility</span>
                  <div className={`font-mono font-bold text-sm mt-0.5 ${polConf > 0.5 ? 'text-emerald-400' : 'text-text-secondary'}`}>
                    {Math.round(polConf * 100)}%
                  </div>
                  <div className="text-[10px] text-text-muted mt-0.5">Program rules met</div>
                </div>
              </div>
            </div>

            {/* Checklist items */}
            {explanation?.checklist && (
              <div className="pt-2 border-t border-border">
                <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted font-mono block mb-2">
                  Deterministic Verification Checklist
                </span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                  {Object.entries(explanation.checklist).map(([chkKey, chkVal]) => (
                    <div key={chkKey} className="flex items-center gap-1.5 p-1.5 rounded bg-surface-2 border border-border">
                      {chkVal ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                      ) : (
                        <XCircle className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
                      )}
                      <span className="font-mono text-text-secondary truncate">{chkKey.replace(/_/g, ' ')}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>
        );
      })()}

      {/* Human Operator Review Panel (Phase 19 Quality Gate) */}
      <Card className="p-5 bg-surface border-border space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-border">
          <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider flex items-center gap-2">
            <UserCheck className="w-4 h-4 text-accent" />
            Operator Review Gate (Human Verification)
          </h2>
          <Badge
            variant={
              finding.human_review_status === 'APPROVED'
                ? 'success'
                : finding.human_review_status === 'REJECTED'
                ? 'danger'
                : 'warning'
            }
            size="sm"
          >
            Review Status: {finding.human_review_status || 'PENDING'}
          </Badge>
        </div>

        {reviewFeedback && (
          <div
            className={`p-3 rounded text-xs ${
              reviewFeedback.type === 'success'
                ? 'bg-emerald-950/40 border border-emerald-800 text-emerald-300'
                : 'bg-red-950/40 border border-red-800 text-red-300'
            }`}
          >
            {reviewFeedback.message}
          </div>
        )}

        <div className="space-y-2">
          <label className="text-xs text-text-secondary font-medium">Review Notes & Operator Justification:</label>
          <textarea
            value={reviewNotes}
            onChange={(e) => setReviewNotes(e.target.value)}
            placeholder="Add rationale for approving, rejecting (false positive), or requesting reverification..."
            rows={2}
            className="w-full text-xs p-2.5 rounded bg-surface-2 border border-border text-text-primary focus:outline-none focus:border-accent"
          />
        </div>

        <div className="flex items-center gap-3 pt-2 flex-wrap">
          <Button
            variant="success"
            size="sm"
            disabled={reviewLoading || !isVerified}
            onClick={() => handleReview('APPROVE')}
            className="flex items-center gap-1.5"
          >
            <ShieldCheck className="w-4 h-4" /> Approve for Report
          </Button>

          <Button
            variant="danger"
            size="sm"
            disabled={reviewLoading}
            onClick={() => handleReview('REJECT')}
            className="flex items-center gap-1.5"
          >
            <XCircle className="w-4 h-4" /> Reject (False Positive)
          </Button>

          <Button
            variant="secondary"
            size="sm"
            disabled={reviewLoading}
            onClick={() => handleReview('REVERIFY')}
            className="flex items-center gap-1.5"
          >
            <RefreshCw className="w-4 h-4" /> Request Re-Verification
          </Button>
        </div>

        {finding.human_reviewed_by && (
          <div className="text-[11px] text-text-muted font-mono pt-2 border-t border-border">
            Reviewed by: <span className="text-text-primary">{finding.human_reviewed_by}</span> at{' '}
            <span>{finding.human_reviewed_at || 'Recently'}</span>
            {finding.human_review_notes && <div>Notes: {finding.human_review_notes}</div>}
          </div>
        )}
      </Card>

      {/* Suggested Fix & Remediation */}
      <Card className="p-5 bg-surface border-border space-y-3">
        <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider pb-2 border-b border-border">
          Suggested Remediation & Fix Guidance
        </h2>
        <div className="text-xs text-text-secondary leading-relaxed">
          {typeof finding.remediation === 'object' && finding.remediation?.recommendation ? (
            <p>{finding.remediation.recommendation}</p>
          ) : (
            <p>
              Implement input sanitization, context-aware encoding, and strict server-side validation.
            </p>
          )}
        </div>
      </Card>
    </div>
  );
}
