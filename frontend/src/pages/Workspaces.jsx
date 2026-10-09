import { useEffect, useState } from 'react';
import { Building2, Plus, RefreshCw, UserPlus, Users } from 'lucide-react';
import {
  addWorkspaceMember,
  createWorkspace,
  getWorkspaceMembers,
  getWorkspaces,
  removeWorkspaceMember,
  updateWorkspaceMember,
} from '../lib/api';

const roles = ['admin', 'member', 'viewer'];

export default function Workspaces() {
  const [workspaces, setWorkspaces] = useState([]);
  const [selectedId, setSelectedId] = useState('');
  const [members, setMembers] = useState([]);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('member');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const selected = workspaces.find((workspace) => workspace.id === selectedId);

  async function loadWorkspaces(preferredId = selectedId) {
    const response = await getWorkspaces();
    const rows = response.data?.data || [];
    setWorkspaces(rows);
    const nextId = rows.some((row) => row.id === preferredId) ? preferredId : rows[0]?.id || '';
    setSelectedId(nextId);
    if (nextId) {
      const memberResponse = await getWorkspaceMembers(nextId);
      setMembers(memberResponse.data?.data || []);
    } else setMembers([]);
  }

  useEffect(() => {
    loadWorkspaces().catch((err) => setError(err.response?.data?.detail || 'Could not load workspaces'));
  }, []);

  async function run(action) {
    setBusy(true);
    setError('');
    try { await action(); } catch (err) {
      setError(err.response?.data?.detail || 'The workspace request failed');
    } finally { setBusy(false); }
  }

  return (
    <div className="max-w-5xl space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">Team workspaces</h1>
          <p className="mt-1 text-sm text-text-secondary">Share campaign access with your organization and manage member roles.</p>
        </div>
        <button onClick={() => run(() => loadWorkspaces())} disabled={busy} className="inline-flex items-center gap-2 rounded border border-border px-3 py-2 text-sm text-text-secondary hover:bg-surface-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>

      {error && <div role="alert" className="rounded border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>}

      <section className="rounded-lg border border-border bg-surface p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold"><Plus className="h-4 w-4 text-accent" /> Create workspace</h2>
        <form className="flex flex-wrap gap-2" onSubmit={(event) => {
          event.preventDefault();
          run(async () => {
            const response = await createWorkspace({ name });
            setName('');
            await loadWorkspaces(response.data?.data?.id);
          });
        }}>
          <input aria-label="Workspace name" value={name} onChange={(event) => setName(event.target.value)} minLength={2} maxLength={120} required placeholder="e.g. AppSec Team" className="min-w-60 flex-1 rounded border border-border bg-background px-3 py-2 text-sm" />
          <button disabled={busy} className="rounded bg-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-50">Create</button>
        </form>
        {!workspaces.length && <p className="mt-3 text-xs text-text-muted">Workspace creation requires an active Team entitlement.</p>}
      </section>

      {selected ? <section className="overflow-hidden rounded-lg border border-border bg-surface">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border p-5">
          <div className="flex items-center gap-3">
            <div className="rounded bg-accent/10 p-2 text-accent"><Building2 className="h-5 w-5" /></div>
            <div><label htmlFor="workspace-select" className="sr-only">Select workspace</label>
              <select id="workspace-select" value={selectedId} onChange={(event) => run(async () => {
                setSelectedId(event.target.value);
                const response = await getWorkspaceMembers(event.target.value);
                setMembers(response.data?.data || []);
              })} className="max-w-64 border-0 bg-transparent p-0 text-lg font-semibold text-text-primary focus:ring-0">
                {workspaces.map((workspace) => <option key={workspace.id} value={workspace.id}>{workspace.name}</option>)}
              </select>
              <p className="mt-1 text-xs text-text-muted">Your role: {selected.role} · {selected.member_count} members</p>
            </div>
          </div>
          {['owner', 'admin'].includes(selected.role) && <form className="flex flex-wrap gap-2" onSubmit={(event) => {
            event.preventDefault();
            run(async () => {
              await addWorkspaceMember(selectedId, { email, role });
              setEmail('');
              await loadWorkspaces(selectedId);
            });
          }}>
            <input type="email" aria-label="Member email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="Existing account email" required className="w-52 rounded border border-border bg-background px-3 py-2 text-sm" />
            <select aria-label="Member role" value={role} onChange={(event) => setRole(event.target.value)} className="rounded border border-border bg-background px-2 py-2 text-sm">
              {roles.filter((option) => selected.role === 'owner' || option !== 'admin').map((option) => <option key={option} value={option}>{option}</option>)}
            </select>
            <button disabled={busy} className="inline-flex items-center gap-2 rounded bg-accent px-3 py-2 text-sm font-medium text-white"><UserPlus className="h-4 w-4" /> Add</button>
          </form>}
        </div>
        <div className="divide-y divide-border">
          {members.map((member) => <div key={member.user_id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
            <div><div className="text-sm font-medium text-text-primary">{member.name || member.email}</div><div className="text-xs text-text-muted">{member.email}</div></div>
            <div className="flex items-center gap-3">
              {selected.role === 'owner' && member.role !== 'owner' ? <select aria-label={`Role for ${member.email}`} value={member.role} onChange={(event) => run(async () => {
                await updateWorkspaceMember(selectedId, member.user_id, { role: event.target.value });
                await loadWorkspaces(selectedId);
              })} className="rounded border border-border bg-background px-2 py-1.5 text-xs">
                {roles.map((option) => <option key={option} value={option}>{option}</option>)}
              </select> : <span className="rounded bg-surface-2 px-2 py-1 text-xs capitalize text-text-secondary">{member.role}</span>}
              {['owner', 'admin'].includes(selected.role) && member.role !== 'owner' && !(selected.role === 'admin' && member.role === 'admin') && <button onClick={() => run(async () => {
                await removeWorkspaceMember(selectedId, member.user_id);
                await loadWorkspaces(selectedId);
              })} className="text-xs text-red-300 hover:text-red-200">Remove</button>}
            </div>
          </div>)}
          {!members.length && <div className="p-8 text-center text-sm text-text-muted"><Users className="mx-auto mb-2 h-5 w-5" />No workspace members yet.</div>}
        </div>
      </section> : <div className="rounded-lg border border-dashed border-border p-10 text-center text-sm text-text-secondary">No workspaces yet. Create one with a Team plan to share campaigns.</div>}
    </div>
  );
}
