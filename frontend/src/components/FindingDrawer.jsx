import { useState } from 'react';
import Drawer from './ui/Drawer';
import Tabs from './ui/Tabs';
import SeverityBadge from './SeverityBadge';

const TABS = ['Overview', 'Proof', 'Remediation', 'Business Impact'];

export default function FindingDrawer({ finding, onClose }) {
  const [activeTab, setActiveTab] = useState('Overview');

  if (!finding) return null;

  return (
    <Drawer
      isOpen={Boolean(finding)}
      onClose={onClose}
      title={
        <div className="space-y-1">
          <SeverityBadge severity={finding.severity} />
          <h2 className="font-display text-lg font-semibold text-text-primary mt-1">
            {finding.title}
          </h2>
        </div>
      }
    >
      <Tabs tabs={TABS} activeTab={activeTab} onChange={setActiveTab} className="mb-4" />

      <div className="space-y-4">
        {activeTab === 'Overview' && (
          <div className="space-y-3 text-sm">
            <div>
              <span className="text-text-secondary">URL:</span>{' '}
              <span className="text-text-primary break-all font-mono text-xs">
                {finding.affected_url}
              </span>
            </div>
            {finding.affected_param && (
              <div>
                <span className="text-text-secondary">Parameter:</span>{' '}
                <code className="font-code text-accent bg-surface-2 px-1.5 py-0.5 rounded text-xs">
                  {finding.affected_param}
                </code>
              </div>
            )}
            <div>
              <span className="text-text-secondary">Category:</span>{' '}
              <span className="text-text-primary">{finding.category}</span>
            </div>
            <div>
              <span className="text-text-secondary">Confidence:</span>{' '}
              <span className="text-text-primary font-semibold">{finding.confidence}%</span>
            </div>
          </div>
        )}

        {activeTab === 'Proof' && (
          <div className="space-y-4">
            <div>
              <h3 className="text-xs font-semibold text-text-secondary mb-2">Payload / Trigger</h3>
              {finding.payload ? (
                <pre className="bg-surface-2 border border-border rounded p-3 font-code text-xs overflow-x-auto text-low whitespace-pre-wrap">
                  {finding.payload}
                </pre>
              ) : (
                <p className="text-text-muted text-sm">No payload available.</p>
              )}
            </div>
            
            <div>
              <h3 className="text-xs font-semibold text-text-secondary mb-2">Proof Response</h3>
              {finding.proof_response ? (
                <pre className="bg-surface-2 border border-border rounded p-3 font-code text-xs overflow-x-auto text-low whitespace-pre-wrap">
                  {finding.proof_response}
                </pre>
              ) : (
                <p className="text-text-muted text-sm">No response evidence available.</p>
              )}
            </div>
          </div>
        )}

        {activeTab === 'Remediation' && (
          <div className="text-sm text-text-primary">
            {finding.remediation?.content ? (
              <pre className="whitespace-pre-wrap font-body text-xs leading-relaxed">
                {finding.remediation.content}
              </pre>
            ) : (
              <p className="text-text-muted">
                Remediation pending — configure API credentials in Settings.
              </p>
            )}
          </div>
        )}

        {activeTab === 'Business Impact' && (
          <div className="text-sm text-text-primary">
            {finding.business_impact?.content ? (
              <pre className="whitespace-pre-wrap font-body text-xs leading-relaxed">
                {finding.business_impact.content}
              </pre>
            ) : (
              <p className="text-text-muted">Business impact analysis pending.</p>
            )}
          </div>
        )}
      </div>
    </Drawer>
  );
}
