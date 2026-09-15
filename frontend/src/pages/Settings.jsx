import { useEffect, useState } from 'react';
import {
  Settings as SettingsIcon,
  ShieldCheck,
  Lock,
  Cpu,
  Database,
  History,
  Key,
  AlertTriangle,
  Save,
} from 'lucide-react';
import { getSettings, saveSettings } from '../lib/api';
import Card from '../components/ui/Card';
import Input from '../components/ui/Input';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import { useToast } from '../hooks/useToast';

export default function Settings() {
  const { addToast } = useToast();
  const [activeTab, setActiveTab] = useState('general');
  const [saving, setSaving] = useState(false);

  const [form, setForm] = useState({
    claude_api_key: '',
    shodan_api_key: '',
    virustotal_api_key: '',
    default_scan_depth: 'normal',
    default_threads: 5,
    default_request_budget: 500,
    max_concurrency: 5,
    alert_email: '',
    slack_webhook: '',
    auto_open_report: true,
  });

  const [configured, setConfigured] = useState({});

  useEffect(() => {
    async function load() {
      try {
        const res = await getSettings();
        if (res.data?.settings) {
          setForm((prev) => ({ ...prev, ...res.data.settings }));
        }
        if (res.data?.api_keys_configured) {
          setConfigured(res.data.api_keys_configured);
        }
      } catch (err) {
        console.error('Error loading settings:', err);
      }
    }
    load();
  }, []);

  async function handleSave(e) {
    e?.preventDefault();
    try {
      setSaving(true);
      await saveSettings(form);
      addToast({
        title: 'Settings Saved',
        message: 'Security operations configuration updated.',
        type: 'success',
      });
    } catch (err) {
      addToast({
        title: 'Save Failed',
        message: err.response?.data?.detail || 'Could not save settings.',
        type: 'error',
      });
    } finally {
      setSaving(false);
    }
  }

  const tabs = [
    { id: 'general', label: 'General', icon: SettingsIcon },
    { id: 'security', label: 'Security & Safety', icon: ShieldCheck },
    { id: 'scope', label: 'Scope Controls', icon: Lock },
    { id: 'runtime', label: 'Runtime & Budget', icon: Cpu },
    { id: 'evidence', label: 'Evidence & Vault', icon: Database },
    { id: 'audit', label: 'Audit & Integrity', icon: History },
    { id: 'apikeys', label: 'API Keys', icon: Key },
  ];

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">
            Security Operations Settings
          </h1>
          <p className="text-xs text-text-secondary mt-0.5">
            Configure system parameters, safety invariants, execution budgets, and evidence retention.
          </p>
        </div>

        <Button
          variant="primary"
          size="sm"
          loading={saving}
          onClick={handleSave}
          className="flex items-center gap-1.5"
        >
          <Save className="w-4 h-4" />
          <span>Save Changes</span>
        </Button>
      </div>

      {/* Tabs Navigation */}
      <div className="flex items-center gap-1 border-b border-border overflow-x-auto pb-1 text-xs">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-3 py-2 rounded-t font-medium transition-colors border-b-2 whitespace-nowrap ${
              activeTab === id
                ? 'border-accent text-accent bg-surface'
                : 'border-transparent text-text-secondary hover:text-text-primary hover:bg-surface-2'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            <span>{label}</span>
          </button>
        ))}
      </div>

      {/* Tab Content Panes */}
      <div className="space-y-6">
        {/* TAB 1: General */}
        {activeTab === 'general' && (
          <Card className="p-5 bg-surface border-border space-y-4">
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider pb-2 border-b border-border">
              General Operations Preferences
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">
                  Default Scan Depth
                </label>
                <select
                  value={form.default_scan_depth}
                  onChange={(e) => setForm({ ...form, default_scan_depth: e.target.value })}
                  className="w-full h-9 rounded bg-surface-2 border border-border px-3 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
                >
                  <option value="quick">Quick (Surface Checks)</option>
                  <option value="normal">Normal (Standard Assessment)</option>
                  <option value="deep">Deep (Full Exhaustive Verification)</option>
                </select>
              </div>

              <Input
                label="Alert Email Address"
                placeholder="security-lead@company.com"
                value={form.alert_email}
                onChange={(e) => setForm({ ...form, alert_email: e.target.value })}
                className="text-xs"
              />

              <Input
                label="Slack Alert Webhook URL"
                placeholder="https://hooks.slack.com/services/..."
                value={form.slack_webhook}
                onChange={(e) => setForm({ ...form, slack_webhook: e.target.value })}
                className="text-xs"
              />
            </div>
          </Card>
        )}

        {/* TAB 2: Security & Safety (Non-Negotiable Controls) */}
        {activeTab === 'security' && (
          <div className="space-y-4">
            <Card className="p-5 bg-surface border-border space-y-4">
              <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider pb-2 border-b border-border">
                Mandatory Safety Invariants
              </h2>

              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 rounded bg-surface-2 border border-border">
                  <div>
                    <div className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5 text-accent" />
                      Scope Enforcement: Default-Deny
                    </div>
                    <div className="text-[11px] text-text-secondary mt-0.5">
                      No network socket or HTTP request is permitted without explicit target scope authorization.
                    </div>
                  </div>
                  <Badge variant="success" size="sm">
                    MANDATORY (FAIL-CLOSED)
                  </Badge>
                </div>

                <div className="flex items-center justify-between p-3 rounded bg-surface-2 border border-border">
                  <div>
                    <div className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-accent" />
                      Pre-Flight Request Gate
                    </div>
                    <div className="text-[11px] text-text-secondary mt-0.5">
                      Out-of-scope targets generate zero network bytes (verified before transport socket opens).
                    </div>
                  </div>
                  <Badge variant="success" size="sm">
                    ACTIVE (0-BYTE GUARD)
                  </Badge>
                </div>

                <div className="flex items-center justify-between p-3 rounded bg-surface-2 border border-border">
                  <div>
                    <div className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                      <Database className="w-3.5 h-3.5 text-accent" />
                      Evidence Secret Redaction
                    </div>
                    <div className="text-[11px] text-text-secondary mt-0.5">
                      Passwords, JWT tokens, cookies, and AWS keys are scrubbed before persistence.
                    </div>
                  </div>
                  <Badge variant="success" size="sm">
                    ENFORCED
                  </Badge>
                </div>
              </div>
            </Card>

            {/* Emergency Kill Switch */}
            <Card className="p-5 bg-surface border-rose-800/40 space-y-3">
              <div className="flex items-center gap-2 text-rose-400 font-bold text-xs uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4" />
                Emergency Operations Kill Switch
              </div>
              <p className="text-xs text-text-secondary leading-relaxed">
                Immediately terminates all active worker leases and aborts all pending campaign tasks.
                Use only when an out-of-bounds target condition or critical system degradation is observed.
              </p>
              <Button
                variant="danger"
                size="sm"
                onClick={() => {
                  if (window.confirm('Trigger global emergency halt? All running scans will be terminated immediately.')) {
                    addToast({
                      title: 'Emergency Halt Triggered',
                      message: 'All worker execution processes signaled to abort.',
                      type: 'error',
                    });
                  }
                }}
              >
                Trigger Global Emergency Halt
              </Button>
            </Card>
          </div>
        )}

        {/* TAB 3: Scope Controls */}
        {activeTab === 'scope' && (
          <Card className="p-5 bg-surface border-border space-y-4">
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider pb-2 border-b border-border">
              Global Scope Evaluation Rules
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-3 rounded bg-surface-2 border border-border space-y-1">
                <span className="font-semibold text-text-primary">Globally Excluded Ports</span>
                <p className="text-[11px] text-text-secondary font-mono">
                  22 (SSH), 25 (SMTP), 3389 (RDP), 445 (SMB)
                </p>
                <div className="text-[10px] text-text-muted mt-1">
                  Excluded to prevent disruptive brute-force attempts on sensitive services.
                </div>
              </div>

              <div className="p-3 rounded bg-surface-2 border border-border space-y-1">
                <span className="font-semibold text-text-primary">Globally Blocked Schemes</span>
                <p className="text-[11px] text-text-secondary font-mono">
                  file://, gopher://, ftp://, dict://
                </p>
                <div className="text-[10px] text-text-muted mt-1">
                  Protects against SSRF scheme manipulation.
                </div>
              </div>
            </div>
          </Card>
        )}

        {/* TAB 4: Runtime & Budget */}
        {activeTab === 'runtime' && (
          <Card className="p-5 bg-surface border-border space-y-4">
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider pb-2 border-b border-border">
              Execution Runtime & Task Leasing
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <Input
                label="Default Campaign Request Budget"
                type="number"
                value={form.default_request_budget || 500}
                onChange={(e) => setForm({ ...form, default_request_budget: parseInt(e.target.value, 10) })}
                className="text-xs font-mono"
              />

              <Input
                label="Default Concurrency Threads"
                type="number"
                value={form.default_threads || 5}
                onChange={(e) => setForm({ ...form, default_threads: parseInt(e.target.value, 10) })}
                className="text-xs font-mono"
                min={1}
                max={20}
              />

              <Input
                label="Worker Lease Timeout (Seconds)"
                type="number"
                value={60}
                disabled
                className="text-xs font-mono opacity-70"
              />
            </div>
          </Card>
        )}

        {/* TAB 5: Evidence & Vault */}
        {activeTab === 'evidence' && (
          <Card className="p-5 bg-surface border-border space-y-4">
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider pb-2 border-b border-border">
              Evidence Vault Configuration
            </h2>

            <div className="space-y-3 text-xs">
              <div className="p-3 rounded bg-surface-2 border border-border">
                <span className="font-semibold text-text-primary">Storage Engine</span>
                <p className="text-[11px] text-text-secondary mt-0.5 font-mono">
                  SQLite (WAL mode with persistent SHA-256 payload content hash)
                </p>
              </div>

              <div className="p-3 rounded bg-surface-2 border border-border">
                <span className="font-semibold text-text-primary">Redaction Regex Rules</span>
                <p className="text-[11px] text-text-secondary mt-0.5 font-mono">
                  Authorization, Cookie, Session, JWT Bearer, AWS Access Keys, API Keys
                </p>
              </div>
            </div>
          </Card>
        )}

        {/* TAB 6: Audit & Integrity */}
        {activeTab === 'audit' && (
          <Card className="p-5 bg-surface border-border space-y-4">
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider pb-2 border-b border-border">
              Audit Non-Repudiation & Chaining
            </h2>

            <div className="space-y-3 text-xs">
              <div className="p-3 rounded bg-surface-2 border border-border">
                <span className="font-semibold text-text-primary">Hash Link Standard</span>
                <p className="text-[11px] text-text-secondary mt-0.5 font-mono">
                  SHA-256(previous_event_hash || event_type || operator_id || timestamp)
                </p>
              </div>
              <div className="p-3 rounded bg-surface-2 border border-border">
                <span className="font-semibold text-text-primary">Retention</span>
                <p className="text-[11px] text-text-secondary mt-0.5">
                  Append-only immutable audit logs preserved permanently in campaign repository.
                </p>
              </div>
            </div>
          </Card>
        )}

        {/* TAB 7: API Keys */}
        {activeTab === 'apikeys' && (
          <Card className="p-5 bg-surface border-border space-y-4">
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider pb-2 border-b border-border">
              External Intelligence API Keys
            </h2>

            <div className="space-y-3">
              <Input
                label="Anthropic Claude API Key (Optional Analysis)"
                placeholder={configured.claude ? '●●●●●●●● (Configured)' : 'sk-ant-...'}
                value={form.claude_api_key}
                onChange={(e) => setForm({ ...form, claude_api_key: e.target.value })}
                className="text-xs font-mono"
              />

              <Input
                label="Shodan API Key (Reconnaissance)"
                placeholder={configured.shodan ? '●●●●●●●● (Configured)' : 'Enter Shodan API key'}
                value={form.shodan_api_key}
                onChange={(e) => setForm({ ...form, shodan_api_key: e.target.value })}
                className="text-xs font-mono"
              />

              <Input
                label="VirusTotal API Key (Threat Intelligence)"
                placeholder={configured.virustotal ? '●●●●●●●● (Configured)' : 'Enter VirusTotal API key'}
                value={form.virustotal_api_key}
                onChange={(e) => setForm({ ...form, virustotal_api_key: e.target.value })}
                className="text-xs font-mono"
              />
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
