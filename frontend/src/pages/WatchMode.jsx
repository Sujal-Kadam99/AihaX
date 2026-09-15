import { useEffect, useState } from 'react';
import { Eye, Trash2, Plus } from 'lucide-react';
import { createWatchSchedule, deleteWatchSchedule, getWatchSchedules } from '../lib/api';
import Input from '../components/ui/Input';
import Select from '../components/ui/Select';
import Button from '../components/ui/Button';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import Alert from '../components/ui/Alert';
import EmptyState from '../components/ui/EmptyState';
import Skeleton from '../components/ui/Skeleton';

const SCHEDULE_TYPES = [
  { id: 'daily', label: 'Daily' },
  { id: 'weekly', label: 'Weekly' },
  { id: 'after_deploy', label: 'After Deploy' },
];

export default function WatchMode() {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [form, setForm] = useState({
    target_url: '',
    watch_name: '',
    schedule_type: 'daily',
    alert_webhook: '',
    alert_email: '',
    scope_notes: '',
    scan_config: {
      scan_depth: 'normal',
      threads: 5,
      waf_bypass: false,
      stealth_mode: false,
      authorization_confirmed: false,
    },
  });

  const loadSchedules = async () => {
    setLoading(true);
    try {
      const res = await getWatchSchedules();
      setSchedules(res.data || []);
    } catch {
      setError('Unable to load watch schedules');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSchedules();
  }, []);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError('');
    setSuccess('');

    if (!form.scan_config.authorization_confirmed) {
      setError('Please confirm authorization before scheduling a watch.');
      setSaving(false);
      return;
    }

    try {
      await createWatchSchedule({
        target_url: form.target_url,
        watch_name: form.watch_name || `Watch ${form.target_url}`,
        schedule_type: form.schedule_type,
        alert_webhook: form.alert_webhook || null,
        alert_email: form.alert_email || null,
        scope_notes: form.scope_notes,
        scan_config: {
          ...form.scan_config,
          target_url: form.target_url,
          authorization_confirmed: form.scan_config.authorization_confirmed,
        },
      });
      setSuccess('Watch schedule created successfully.');
      setForm({
        ...form,
        target_url: '',
        watch_name: '',
        alert_webhook: '',
        alert_email: '',
        scope_notes: '',
      });
      loadSchedules();
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not create watch schedule');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    setLoading(true);
    setError('');
    try {
      await deleteWatchSchedule(id);
      loadSchedules();
    } catch {
      setError('Unable to remove schedule');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="font-display text-2xl font-bold text-text-primary mb-1">Watch Mode</h1>
        <p className="text-text-secondary text-sm max-w-2xl">
          Schedule continuous monitoring with regression detection, delta reports, and webhook alerts.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.3fr_0.7fr]">
        <Card>
          <CardHeader className="flex flex-row items-center gap-3 space-y-0">
            <Eye className="w-5 h-5 text-accent" />
            <CardTitle>Create Watch Schedule</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <Input
                  label="Target URL *"
                  value={form.target_url}
                  onChange={(e) => setForm({ ...form, target_url: e.target.value })}
                  placeholder="https://example.com"
                  required
                />
                <Input
                  label="Watch Name"
                  value={form.watch_name}
                  onChange={(e) => setForm({ ...form, watch_name: e.target.value })}
                  placeholder="Optional friendly name"
                />
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <Select
                  label="Schedule"
                  value={form.schedule_type}
                  onChange={(e) => setForm({ ...form, schedule_type: e.target.value })}
                >
                  {SCHEDULE_TYPES.map((type) => (
                    <option key={type.id} value={type.id}>
                      {type.label}
                    </option>
                  ))}
                </Select>
                <Input
                  label="Webhook Alert"
                  value={form.alert_webhook}
                  onChange={(e) => setForm({ ...form, alert_webhook: e.target.value })}
                  placeholder="https://hooks.example.com/alert"
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-text-secondary">
                  Scope / Authorization Notes *
                </label>
                <textarea
                  value={form.scope_notes}
                  onChange={(e) => setForm({ ...form, scope_notes: e.target.value })}
                  rows={4}
                  className="w-full bg-surface-2 border border-border rounded text-text-primary text-sm p-3 focus:outline-none focus:ring-2 focus:ring-accent"
                  placeholder="Document permitted targets, credentials, and in-scope systems..."
                  required
                />
              </div>

              <label className="flex items-start gap-3 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.scan_config.authorization_confirmed}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      scan_config: {
                        ...form.scan_config,
                        authorization_confirmed: e.target.checked,
                      },
                    })
                  }
                  className="mt-1 accent-accent"
                />
                <span className="text-text-primary text-xs">
                  I confirm I have written authorization to scan this target. Unauthorized tests are prohibited.
                </span>
              </label>

              {error && <Alert variant="destructive">{error}</Alert>}
              {success && <Alert variant="success">{success}</Alert>}

              <Button type="submit" isLoading={saving} startIcon={Plus} className="w-full">
                Schedule Watch
              </Button>
            </form>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Active Watches</CardTitle>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="space-y-2">
                  <Skeleton className="h-12 w-full" />
                  <Skeleton className="h-12 w-full" />
                </div>
              ) : schedules.length === 0 ? (
                <EmptyState
                  title="No Active Watches"
                  description="Create a watch schedule to enable automated continuous penetration testing."
                />
              ) : (
                <div className="space-y-3">
                  {schedules.map((schedule) => (
                    <div key={schedule.id} className="rounded border border-border p-4 bg-surface-2">
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <h3 className="font-medium text-sm text-text-primary">{schedule.watch_name}</h3>
                          <p className="text-xs font-mono text-text-secondary">{schedule.target_url}</p>
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          startIcon={Trash2}
                          onClick={() => handleDelete(schedule.id)}
                          className="text-critical hover:bg-critical-bg"
                        >
                          Remove
                        </Button>
                      </div>
                      <div className="mt-3 grid gap-1 text-xs text-text-secondary">
                        <div>Schedule: {schedule.schedule_type}</div>
                        <div>Next Run: {schedule.next_run ?? 'Pending'}</div>
                        <div>Delta: {schedule.delta_summary || 'No changes detected yet'}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
