import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { startScan } from '../lib/api';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Select from '../components/ui/Select';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import Alert from '../components/ui/Alert';
import { Shield, Server, FileText, CheckCircle, Sliders, Target, Ban } from 'lucide-react';

const MODES = [
  { id: 'safe', label: 'Safe Mode (Recommended)', desc: 'Conservative rate limits and safe checks for bug bounty hunting' },
  { id: 'passive', label: 'Passive Mode', desc: 'Non-intrusive metadata, DNS, and TLS inspection (zero injection)' },
  { id: 'standard', label: 'Standard Mode', desc: 'Full active penetration testing pipeline for authorized assets' },
];

const scanSchema = z.object({
  target_url: z.string().url('Must be a valid HTTP/HTTPS URL'),
  program_name: z.string().optional(),
  in_scope_assets: z.string().optional(),
  out_of_scope_assets: z.string().optional(),
  industry: z.string().optional(),
  scan_mode: z.enum(['safe', 'passive', 'standard', 'bugbounty', 'compliance', 'watch']).default('safe'),
  report_format: z.enum(['executive', 'bugbounty', 'full']).default('full'),
  scan_depth: z.enum(['light', 'normal', 'deep']).default('normal'),
  threads: z.preprocess((val) => Number(val), z.number().min(1).max(20)).default(5),
  rate_limit_rps: z.preprocess((val) => Number(val), z.number().min(1).max(100)).default(10),
  max_concurrency: z.preprocess((val) => Number(val), z.number().min(1).max(20)).default(5),
  waf_bypass: z.boolean().default(false),
  stealth_mode: z.boolean().default(false),
  username: z.string().optional(),
  password: z.string().optional(),
  username2: z.string().optional(),
  password2: z.string().optional(),
  two_fa_type: z.enum(['none', 'email', 'sms', 'totp']).default('none'),
  totp_secret: z.string().optional(),
  bearer_token: z.string().optional(),
  admin_url: z.string().optional(),
  admin_username: z.string().optional(),
  admin_password: z.string().optional(),
  authorization_confirmed: z.literal(true, {
    errorMap: () => ({ message: 'You must confirm authorization before starting a scan' }),
  }),
  scope_notes: z.string().optional(),
});

const STEPS = [
  { id: 'target', title: 'Target & Scope', icon: Server },
  { id: 'auth', title: 'Tuning & Rate Limits', icon: Sliders },
  { id: 'authorize', title: 'Authorization', icon: FileText },
];

export default function NewScan() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [currentStep, setCurrentStep] = useState(0);

  const {
    register,
    handleSubmit,
    watch,
    trigger,
    setValue,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(scanSchema),
    defaultValues: {
      target_url: '',
      program_name: '',
      in_scope_assets: '',
      out_of_scope_assets: '',
      scan_mode: 'safe',
      report_format: 'full',
      scan_depth: 'normal',
      threads: 5,
      rate_limit_rps: 10,
      max_concurrency: 5,
      waf_bypass: false,
      stealth_mode: false,
      two_fa_type: 'none',
    },
    mode: 'onTouched',
  });

  const twoFaType = watch('two_fa_type');
  const selectedMode = watch('scan_mode');
  const targetUrl = watch('target_url');

  const handleNext = async () => {
    let fieldsToValidate = [];
    if (currentStep === 0) fieldsToValidate = ['target_url', 'scan_mode', 'report_format'];
    else if (currentStep === 1) fieldsToValidate = ['scan_depth', 'threads', 'rate_limit_rps', 'max_concurrency', 'two_fa_type'];

    const isValid = await trigger(fieldsToValidate);
    if (isValid) setCurrentStep((prev) => Math.min(prev + 1, STEPS.length - 1));
  };

  const handleBack = () => setCurrentStep((prev) => Math.max(prev - 1, 0));

  const onSubmit = async (data) => {
    setLoading(true);
    setError('');
    try {
      const inScopeList = data.in_scope_assets
        ? data.in_scope_assets.split('\n').map((s) => s.trim()).filter(Boolean)
        : [];
      const outScopeList = data.out_of_scope_assets
        ? data.out_of_scope_assets.split('\n').map((s) => s.trim()).filter(Boolean)
        : [];

      const payload = {
        target_url: data.target_url,
        industry: data.industry || null,
        scan_depth: data.scan_depth,
        threads: Number(data.threads),
        rate_limit: {
          requests_per_second: Number(data.rate_limit_rps),
          max_concurrency: Number(data.max_concurrency),
        },
        waf_bypass: data.waf_bypass,
        stealth_mode: data.stealth_mode,
        scan_mode: data.scan_mode,
        report_format: data.report_format,
        two_fa_type: data.two_fa_type,
        in_scope_assets: inScopeList.length > 0 ? inScopeList : undefined,
        out_of_scope_assets: outScopeList.length > 0 ? outScopeList : undefined,
        primary_creds: data.username ? { username: data.username, password: data.password } : null,
        secondary_creds: data.username2
          ? { username: data.username2, password: data.password2 }
          : null,
        authorization_confirmed: data.authorization_confirmed,
        scope_notes: data.scope_notes || null,
      };

      if (data.two_fa_type === 'totp' && data.totp_secret) {
        payload.two_fa_config = { totp_secret: data.totp_secret };
      }

      const apiAuth = {};
      if (data.bearer_token) apiAuth.bearer_token = data.bearer_token;
      if (data.admin_url) apiAuth.admin_url = data.admin_url;
      if (data.admin_username) apiAuth.admin_username = data.admin_username;
      if (data.admin_password) apiAuth.admin_password = data.admin_password;
      if (Object.keys(apiAuth).length > 0) payload.api_auth = apiAuth;

      const res = await startScan(payload);
      navigate(`/scan/${res.data.scan_id}`);
    } catch (err) {
      const detail = err.response?.data?.detail;
      setError(
        typeof detail === 'string'
          ? detail
          : Array.isArray(detail)
            ? detail.map((d) => d.msg).join(', ')
            : 'Failed to start scan'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-8">
      <div className="text-center space-y-2">
        <h1 className="font-display text-3xl font-bold text-text-primary">Configure Bug Bounty Assessment</h1>
        <p className="text-text-secondary">Define target scope, safety parameters, and authorization constraints.</p>
      </div>

      <div className="flex items-center justify-between relative max-w-2xl mx-auto mb-8">
        <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-surface-3 -z-10 -translate-y-1/2" />
        {STEPS.map((step, idx) => {
          const isActive = idx === currentStep;
          const isCompleted = idx < currentStep;
          const Icon = step.icon;
          return (
            <div key={step.id} className="flex flex-col items-center gap-2 bg-background px-4">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center transition-colors ${
                  isActive
                    ? 'bg-accent text-white shadow-lg shadow-accent/20'
                    : isCompleted
                      ? 'bg-success text-white'
                      : 'bg-surface-2 text-text-muted border border-border-subtle'
                }`}
              >
                {isCompleted ? <CheckCircle className="w-5 h-5" /> : <Icon className="w-5 h-5" />}
              </div>
              <span className={`text-xs font-semibold ${isActive ? 'text-accent' : 'text-text-secondary'}`}>
                {step.title}
              </span>
            </div>
          );
        })}
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6 max-w-3xl mx-auto">
        {currentStep === 0 && (
          <div className="space-y-6 slide-in">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="w-5 h-5 text-accent" /> Target & Scope Definition
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <Input
                  label="Primary Target URL *"
                  error={errors.target_url?.message}
                  placeholder="https://app.example.com"
                  {...register('target_url')}
                />

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="block text-sm font-medium text-text-primary flex items-center gap-1.5">
                      <CheckCircle className="w-4 h-4 text-success" /> In-Scope Assets (One per line)
                    </label>
                    <textarea
                      {...register('in_scope_assets')}
                      rows={3}
                      placeholder="*.example.com&#10;api.example.com&#10;https://example.com/v1/*"
                      className="w-full bg-surface border border-border-subtle rounded-lg text-text-primary text-xs font-mono p-3 focus:outline-none focus:ring-2 focus:ring-accent"
                    />
                    <span className="text-[11px] text-text-muted">Wildcards (*.domain.com) and URL prefixes supported</span>
                  </div>

                  <div className="space-y-2">
                    <label className="block text-sm font-medium text-text-primary flex items-center gap-1.5">
                      <Ban className="w-4 h-4 text-critical" /> Out-of-Scope Exclusions (One per line)
                    </label>
                    <textarea
                      {...register('out_of_scope_assets')}
                      rows={3}
                      placeholder="admin.example.com&#10;billing.example.com&#10;/internal/*"
                      className="w-full bg-surface border border-border-subtle rounded-lg text-text-primary text-xs font-mono p-3 focus:outline-none focus:ring-2 focus:ring-critical"
                    />
                    <span className="text-[11px] text-text-muted">Explicit exclusions always override inclusions</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <div className="space-y-3">
              <h3 className="font-medium text-text-primary text-sm">Scan Mode</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {MODES.map((mode) => (
                  <button
                    key={mode.id}
                    type="button"
                    onClick={() => setValue('scan_mode', mode.id)}
                    className={`text-left p-4 rounded-xl border transition-all ${
                      selectedMode === mode.id
                        ? 'border-accent bg-accent/10 ring-1 ring-accent'
                        : 'border-border-subtle bg-surface hover:border-border-strong hover:bg-surface-2'
                    }`}
                  >
                    <p className="font-semibold text-text-primary text-sm">{mode.label}</p>
                    <p className="text-xs text-text-secondary mt-1">{mode.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-3 mt-4">
              <Select label="Report Export Format" {...register('report_format')}>
                <option value="full">Full Bug Bounty Package (Executive + Findings + PoCs)</option>
                <option value="bugbounty">Bug Bounty Report (HackerOne / Bugcrowd standard)</option>
                <option value="executive">Executive Summary Only</option>
              </Select>
            </div>
          </div>
        )}

        {currentStep === 1 && (
          <div className="space-y-6 slide-in">
            <Card>
              <CardHeader><CardTitle>Rate Limits & Engine Tuning</CardTitle></CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <label className="block text-sm font-medium text-text-primary">Requests Per Second (RPS)</label>
                      <span className="text-xs font-mono bg-surface-2 px-2 py-1 rounded text-accent font-bold">
                        {watch('rate_limit_rps')} req/sec
                      </span>
                    </div>
                    <input
                      type="range"
                      {...register('rate_limit_rps')}
                      min={1}
                      max={50}
                      className="w-full accent-accent h-2 bg-surface-3 rounded-lg appearance-none cursor-pointer"
                    />
                    <p className="text-[11px] text-text-muted">Protects target services from denial-of-service</p>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <label className="block text-sm font-medium text-text-primary">Max Concurrency</label>
                      <span className="text-xs font-mono bg-surface-2 px-2 py-1 rounded text-text-secondary font-bold">
                        {watch('max_concurrency')} concurrent
                      </span>
                    </div>
                    <input
                      type="range"
                      {...register('max_concurrency')}
                      min={1}
                      max={15}
                      className="w-full accent-accent h-2 bg-surface-3 rounded-lg appearance-none cursor-pointer"
                    />
                    <p className="text-[11px] text-text-muted">Parallel worker limit across checks</p>
                  </div>
                </div>

                <div className="space-y-1.5 pt-4 border-t border-border-subtle">
                  <label className="block text-sm font-medium text-text-primary">Scan Depth</label>
                  <div className="flex gap-4">
                    {['light', 'normal', 'deep'].map((d) => (
                      <label key={d} className="flex items-center gap-2 cursor-pointer bg-surface-2 px-4 py-2 rounded-md border border-border-subtle hover:border-border-strong">
                        <input type="radio" {...register('scan_depth')} value={d} className="accent-accent" />
                        <span className="text-sm capitalize text-text-primary">{d}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle>Authentication Credentials (Optional)</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <Input label="Username (Account 1)" placeholder="user@example.com" {...register('username')} />
                  <Input label="Password" type="password" placeholder="••••••••" {...register('password')} />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <Input label="Username (Account 2 - IDOR)" placeholder="user2@example.com" {...register('username2')} />
                  <Input label="Password" type="password" {...register('password2')} />
                </div>

                <Select label="2FA Type" {...register('two_fa_type')}>
                  <option value="none">None</option>
                  <option value="email">Email OTP</option>
                  <option value="sms">SMS OTP (Twilio)</option>
                  <option value="totp">TOTP (Secret Key)</option>
                </Select>
                {twoFaType === 'totp' && (
                  <Input label="TOTP Secret Key" placeholder="Base32 secret key" {...register('totp_secret')} />
                )}

                <div className="pt-4 border-t border-border-subtle">
                  <Input label="API Bearer Token" placeholder="Bearer eyJ..." {...register('bearer_token')} />
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {currentStep === 2 && (
          <div className="space-y-6 slide-in">
            <Card className="border-warning/50 bg-warning/5">
              <CardHeader>
                <CardTitle className="text-warning flex items-center gap-2">
                  <Shield className="w-5 h-5" /> Mandatory Legal Authorization
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-3">
                  <label className="flex items-start gap-4 cursor-pointer p-4 rounded-xl border border-warning/20 bg-warning/10 hover:bg-warning/20 transition-colors">
                    <input
                      type="checkbox"
                      {...register('authorization_confirmed')}
                      className="mt-1 w-5 h-5 accent-warning rounded"
                    />
                    <div>
                      <p className="font-semibold text-sm text-text-primary">
                        I confirm I have explicit, written authorization to perform security testing on {targetUrl || 'this target'}.
                      </p>
                      <p className="text-xs text-text-secondary mt-1">
                        AihaX actively tests for vulnerabilities and strictly enforces bug bounty scope rules. Unauthorized scanning is illegal.
                      </p>
                    </div>
                  </label>
                  {errors.authorization_confirmed && (
                    <Alert variant="destructive" className="py-2">{errors.authorization_confirmed.message}</Alert>
                  )}
                </div>

                <div className="space-y-2">
                  <label className="block text-sm font-medium text-text-primary">
                    Scope & Program Notes
                  </label>
                  <textarea
                    {...register('scope_notes')}
                    rows={4}
                    placeholder="Enter bug bounty program policy URL, HackerOne/Bugcrowd program handle, or written engagement details..."
                    className="w-full bg-surface border border-border-strong rounded-lg text-text-primary text-sm p-4 focus:outline-none focus:ring-2 focus:ring-accent"
                  />
                  <p className="text-xs text-text-muted">Recorded in the audit trail and report metadata.</p>
                </div>
              </CardContent>
            </Card>
            {error && <Alert variant="destructive" title="Submission Failed">{error}</Alert>}
          </div>
        )}

        <div className="flex items-center justify-between pt-6 border-t border-border-subtle">
          <Button type="button" variant="ghost" onClick={handleBack} disabled={currentStep === 0}>
            Back
          </Button>

          {currentStep < STEPS.length - 1 ? (
            <Button type="button" onClick={handleNext} className="min-w-[120px]">
              Next Step
            </Button>
          ) : (
            <Button
              type="submit"
              isLoading={loading}
              variant="primary"
              className="min-w-[150px] font-bold"
            >
              LAUNCH SCAN
            </Button>
          )}
        </div>
      </form>
    </div>
  );
}
