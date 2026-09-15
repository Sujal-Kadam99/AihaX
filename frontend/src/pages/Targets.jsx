import { useState, useEffect } from 'react';
import {
  Target,
  Plus,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { getPrograms, createProgram, validateTargetScope } from '../lib/api';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Modal from '../components/ui/Modal';
import { useToast } from '../hooks/useToast';

export default function Targets() {
  const { addToast } = useToast();
  const [programs, setPrograms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedProgram, setSelectedProgram] = useState(null);

  // Scope Testing Tool State
  const [testTarget, setTestTarget] = useState('');
  const [testPort, setTestPort] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testingScope, setTestingScope] = useState(false);

  // New Program Modal
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newProgram, setNewProgram] = useState({
    name: '',
    description: '',
    in_scope_assets: 'https://example.com/*',
    out_of_scope_assets: 'https://example.com/internal/*',
    allowed_ports: '80, 443',
    excluded_ports: '22, 3389, 25',
    allowed_schemes: 'http, https',
    excluded_paths: '/admin/*, /internal/*',
  });

  useEffect(() => {
    loadPrograms();
  }, []);

  async function loadPrograms() {
    try {
      setLoading(true);
      const res = await getPrograms();
      const list = res.data?.data || res.data || [];
      setPrograms(list);
      if (list.length > 0 && !selectedProgram) {
        setSelectedProgram(list[0]);
      }
    } catch (err) {
      console.error('Error fetching programs:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleValidateScope(e) {
    e?.preventDefault();
    if (!testTarget || !selectedProgram) return;

    try {
      setTestingScope(true);
      setTestResult(null);
      const portVal = testPort ? parseInt(testPort, 10) : undefined;
      const res = await validateTargetScope(selectedProgram.id, testTarget, portVal);
      setTestResult(res.data?.data || res.data);
    } catch (err) {
      addToast({
        title: 'Validation Error',
        message: err.response?.data?.detail || 'Failed to evaluate scope.',
        type: 'error',
      });
    } finally {
      setTestingScope(false);
    }
  }

  async function handleCreateProgram(e) {
    e.preventDefault();
    try {
      const payload = {
        name: newProgram.name,
        description: newProgram.description,
        scope: {
          in_scope_assets: newProgram.in_scope_assets.split(',').map((s) => s.trim()).filter(Boolean),
          out_of_scope_assets: newProgram.out_of_scope_assets.split(',').map((s) => s.trim()).filter(Boolean),
          allowed_ports: newProgram.allowed_ports.split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n)),
          excluded_ports: newProgram.excluded_ports.split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n)),
          allowed_schemes: newProgram.allowed_schemes.split(',').map((s) => s.trim()).filter(Boolean),
          excluded_paths: newProgram.excluded_paths.split(',').map((s) => s.trim()).filter(Boolean),
        },
      };

      await createProgram(payload);
      addToast({
        title: 'Program Created',
        message: `Authorized program "${newProgram.name}" registered successfully.`,
        type: 'success',
      });
      setIsModalOpen(false);
      loadPrograms();
    } catch (err) {
      addToast({
        title: 'Failed to Create Program',
        message: err.response?.data?.detail || 'An error occurred.',
        type: 'error',
      });
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">
            Target & Scope Management
          </h1>
          <p className="text-xs text-text-secondary mt-0.5">
            Configure authorized bug-bounty scopes and test deterministic scope decisions before execution.
          </p>
        </div>
        <Button
          variant="primary"
          size="sm"
          className="flex items-center gap-1.5"
          onClick={() => setIsModalOpen(true)}
        >
          <Plus className="w-4 h-4" />
          <span>New Target Program</span>
        </Button>
      </div>

      {/* Main Content Layout: Programs List + Scope Rules & Live Validator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Programs Selector */}
        <div className="space-y-4">
          <Card className="p-0 bg-surface border-border overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-surface-2/40">
              <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                Authorized Programs ({programs.length})
              </h2>
            </div>

            {programs.length === 0 && !loading ? (
              <div className="p-6 text-center space-y-2">
                <Target className="w-8 h-8 mx-auto text-text-muted" />
                <p className="text-xs text-text-secondary">No programs defined yet.</p>
                <Button size="xs" variant="secondary" onClick={() => setIsModalOpen(true)}>
                  Create Program
                </Button>
              </div>
            ) : (
              <div className="divide-y divide-border">
                {programs.map((prog) => (
                  <div
                    key={prog.id}
                    onClick={() => {
                      setSelectedProgram(prog);
                      setTestResult(null);
                    }}
                    className={`p-3.5 cursor-pointer transition-colors ${
                      selectedProgram?.id === prog.id
                        ? 'bg-accent/10 border-l-2 border-accent'
                        : 'hover:bg-surface-2/50'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-text-primary">{prog.name}</span>
                      <Badge variant="accent" size="xs">
                        {prog.status || 'AUTHORIZED'}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between mt-1 text-[11px] text-text-muted">
                      <span className="truncate max-w-[140px]">{prog.description || 'No description'}</span>
                      <span className="font-mono text-[10px]">
                        {prog.active_campaigns_count || 0} active / {prog.total_campaigns_count || 0} total
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>

        {/* Right 2 Columns: Selected Program Details & Live Scope Validator */}
        <div className="lg:col-span-2 space-y-6">
          {selectedProgram ? (
            <>
              {/* Program Scope Summary Card */}
              <Card className="p-5 bg-surface border-border space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-border">
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-sm font-bold text-text-primary">{selectedProgram.name}</h2>
                      <Badge variant="accent" size="xs">
                        {selectedProgram.status || 'AUTHORIZED'}
                      </Badge>
                    </div>
                    <p className="text-xs text-text-secondary mt-0.5">
                      {selectedProgram.description || 'Target scope specification'}
                    </p>
                  </div>
                  <div className="text-right">
                    <div className="text-xs font-mono text-text-muted">
                      ID: {selectedProgram.id?.slice(0, 8)}...
                    </div>
                    <div className="text-[11px] text-accent font-mono mt-0.5">
                      {selectedProgram.active_campaigns_count || 0} Active Campaign(s)
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  {/* In-Scope Rules */}
                  <div className="p-3 rounded bg-surface-2 border border-border space-y-1.5">
                    <div className="flex items-center gap-1.5 font-semibold text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>In-Scope Assets</span>
                    </div>
                    <ul className="text-[11px] font-mono text-text-secondary space-y-1">
                      {selectedProgram.scope?.in_scope_assets?.map((a, i) => (
                        <li key={i} className="truncate">
                          &bull; {a}
                        </li>
                      )) || <li>&bull; None defined</li>}
                    </ul>
                  </div>

                  {/* Out-of-Scope Rules */}
                  <div className="p-3 rounded bg-surface-2 border border-border space-y-1.5">
                    <div className="flex items-center gap-1.5 font-semibold text-rose-400">
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Explicit Out-of-Scope</span>
                    </div>
                    <ul className="text-[11px] font-mono text-text-secondary space-y-1">
                      {selectedProgram.scope?.out_of_scope_assets?.map((a, i) => (
                        <li key={i} className="truncate">
                          &bull; {a}
                        </li>
                      )) || <li>&bull; None defined</li>}
                    </ul>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs pt-1">
                  <div className="p-2.5 rounded bg-surface-2 border border-border">
                    <span className="text-text-muted text-[10px] uppercase font-semibold">
                      Allowed Ports
                    </span>
                    <div className="font-mono text-[11px] text-text-primary mt-0.5">
                      {selectedProgram.scope?.allowed_ports?.join(', ') || 'All (Default)'}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-surface-2 border border-border">
                    <span className="text-text-muted text-[10px] uppercase font-semibold">
                      Excluded Ports
                    </span>
                    <div className="font-mono text-[11px] text-rose-400 mt-0.5">
                      {selectedProgram.scope?.excluded_ports?.join(', ') || '22, 25, 3389'}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-surface-2 border border-border col-span-2 sm:col-span-1">
                    <span className="text-text-muted text-[10px] uppercase font-semibold">
                      Schemes
                    </span>
                    <div className="font-mono text-[11px] text-text-primary mt-0.5">
                      {selectedProgram.scope?.allowed_schemes?.join(', ') || 'http, https'}
                    </div>
                  </div>
                </div>
              </Card>

              {/* Campaign Assignments & Lifecycle Status Card */}
              <Card className="p-5 bg-surface border-border space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                    Campaign Assignments & Target Status
                  </h3>
                  <span className="text-[11px] font-mono text-text-muted">
                    {selectedProgram.campaigns?.length || 0} total assignments
                  </span>
                </div>

                {(!selectedProgram.campaigns || selectedProgram.campaigns.length === 0) ? (
                  <div className="p-4 text-center rounded bg-surface-2/40 border border-border text-xs text-text-muted">
                    No campaigns currently assigned to this program scope.
                  </div>
                ) : (
                  <div className="divide-y divide-border rounded bg-surface-2/40 border border-border overflow-hidden">
                    {selectedProgram.campaigns.map((camp) => {
                      const isCampActive = camp.status === 'RUNNING' || camp.status === 'PAUSED' || camp.status === 'AUTHORIZED';
                      const assignmentStatus = isCampActive
                        ? 'ACTIVE'
                        : camp.status === 'CANCELLED'
                        ? 'RELEASED (Cancelled)'
                        : camp.status === 'COMPLETED'
                        ? 'RELEASED (Completed)'
                        : 'INACTIVE';
                      return (
                        <div key={camp.id} className="p-3 flex items-center justify-between text-xs">
                          <div>
                            <div className="font-semibold text-text-primary flex items-center gap-2">
                              <span>{camp.name}</span>
                              <Badge
                                variant={
                                  camp.status === 'RUNNING'
                                    ? 'success'
                                    : camp.status === 'PAUSED'
                                    ? 'warning'
                                    : camp.status === 'COMPLETED'
                                    ? 'info'
                                    : camp.status === 'CANCELLED'
                                    ? 'danger'
                                    : 'secondary'
                                }
                                size="xs"
                              >
                                {camp.status}
                              </Badge>
                            </div>
                            <div className="font-mono text-[11px] text-text-secondary mt-0.5">
                              {camp.target_url}
                            </div>
                          </div>
                          <div className="text-right font-mono text-[11px]">
                            <span className={isCampActive ? 'text-emerald-400 font-semibold' : 'text-text-muted'}>
                              {assignmentStatus}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </Card>

              {/* Interactive Scope Evaluation Tool */}
              <Card className="p-5 bg-surface border-border space-y-4">
                <div>
                  <h3 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                    Interactive Scope Pre-Flight Evaluation
                  </h3>
                  <p className="text-xs text-text-secondary mt-0.5">
                    Test target URLs against the active scope validator. Zero network packets are sent during evaluation.
                  </p>
                </div>

                <form onSubmit={handleValidateScope} className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1">
                    <Input
                      placeholder="https://example.com/api/v1"
                      value={testTarget}
                      onChange={(e) => setTestTarget(e.target.value)}
                      className="text-xs font-mono"
                    />
                  </div>
                  <div className="w-28">
                    <Input
                      placeholder="Port (80)"
                      value={testPort}
                      onChange={(e) => setTestPort(e.target.value)}
                      className="text-xs font-mono"
                    />
                  </div>
                  <Button
                    type="submit"
                    variant="secondary"
                    size="sm"
                    loading={testingScope}
                    disabled={!testTarget}
                    className="flex-shrink-0"
                  >
                    Evaluate Scope
                  </Button>
                </form>

                {/* Scope Result Banner */}
                {testResult && (
                  <div
                    className={`p-3.5 rounded border text-xs ${
                      testResult.allowed
                        ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-300'
                        : 'bg-rose-950/30 border-rose-800/60 text-rose-300'
                    }`}
                  >
                    <div className="flex items-center gap-2 font-bold text-sm">
                      {testResult.allowed ? (
                        <>
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          <span>● SCOPE VALIDATED</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-4 h-4 text-rose-400" />
                          <span>● OUT OF SCOPE — BLOCKED</span>
                        </>
                      )}
                    </div>
                    <div className="mt-1 font-mono text-[11px] opacity-90">
                      Status: {testResult.status} &bull; {testResult.reason}
                    </div>
                    {!testResult.allowed && (
                      <div className="mt-1.5 text-[10px] text-rose-400 font-semibold">
                        Safety Invariant: Requests to this target will be terminated before any network transmission.
                      </div>
                    )}
                  </div>
                )}
              </Card>
            </>
          ) : (
            <Card className="p-8 text-center bg-surface border-border">
              <p className="text-xs text-text-secondary">Select a program to view its scope.</p>
            </Card>
          )}
        </div>
      </div>

      {/* New Program Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Register Authorized Target Program"
      >
        <form onSubmit={handleCreateProgram} className="space-y-4">
          <Input
            label="Program Name"
            placeholder="e.g. Acme Security Program"
            value={newProgram.name}
            onChange={(e) => setNewProgram({ ...newProgram, name: e.target.value })}
            required
          />

          <Input
            label="Description / Policy Link"
            placeholder="e.g. Authorized Bug Bounty Scope"
            value={newProgram.description}
            onChange={(e) => setNewProgram({ ...newProgram, description: e.target.value })}
          />

          <Input
            label="In-Scope Assets (comma separated)"
            placeholder="https://example.com/*, *.example.com"
            value={newProgram.in_scope_assets}
            onChange={(e) => setNewProgram({ ...newProgram, in_scope_assets: e.target.value })}
            required
          />

          <Input
            label="Explicit Out-of-Scope Assets"
            placeholder="https://example.com/internal/*, admin.example.com"
            value={newProgram.out_of_scope_assets}
            onChange={(e) => setNewProgram({ ...newProgram, out_of_scope_assets: e.target.value })}
          />

          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Allowed Ports"
              placeholder="80, 443"
              value={newProgram.allowed_ports}
              onChange={(e) => setNewProgram({ ...newProgram, allowed_ports: e.target.value })}
            />
            <Input
              label="Excluded Ports"
              placeholder="22, 25, 3389"
              value={newProgram.excluded_ports}
              onChange={(e) => setNewProgram({ ...newProgram, excluded_ports: e.target.value })}
            />
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-border">
            <Button type="button" variant="secondary" onClick={() => setIsModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="primary">
              Register Program
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
