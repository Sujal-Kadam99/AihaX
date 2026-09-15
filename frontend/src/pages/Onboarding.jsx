import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Button from '../components/ui/Button';
import { Shield, Target, Zap, CheckCircle2 } from 'lucide-react';
import { startScan } from '../lib/api';

export default function Onboarding() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);

  const handleStart = async () => {
    if (!target) return;
    setLoading(true);
    try {
      const res = await startScan({ 
          target_url: target, 
          scan_depth: 'normal', 
          scan_mode: 'standard', 
          industry: 'General',
          admin_mode: false,
          threads: 5
      });
      navigate(`/scan/${res.data.scan_id}`);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-bg-app flex items-center justify-center p-6">
      <div className="max-w-xl w-full bg-surface-1 border border-border-subtle rounded-xl p-8 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-accent via-accent-hover to-accent" />
        
        {step === 1 && (
          <div className="space-y-6">
            <div className="text-center space-y-2">
              <h1 className="text-2xl font-bold text-text-primary">Welcome to AihaX</h1>
              <p className="text-text-secondary text-sm">
                Next-generation automated AI-powered penetration testing. Get enterprise-grade vulnerability intelligence and verified proofs of concept in minutes.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 my-6">
              <div className="bg-surface-2 p-4 rounded-lg border border-border-subtle flex flex-col items-center text-center space-y-2">
                <Target className="w-6 h-6 text-accent" />
                <span className="font-semibold text-xs text-text-primary">Autonomous Recon</span>
                <span className="text-[10px] text-text-muted">Subdomains, tech stack, and entry points</span>
              </div>
              <div className="bg-surface-2 p-4 rounded-lg border border-border-subtle flex flex-col items-center text-center space-y-2">
                <Zap className="w-6 h-6 text-warning" />
                <span className="font-semibold text-xs text-text-primary">Active Exploitation</span>
                <span className="text-[10px] text-text-muted">Context-aware payloads & exploit chains</span>
              </div>
              <div className="bg-surface-2 p-4 rounded-lg border border-border-subtle flex flex-col items-center text-center space-y-2">
                <CheckCircle2 className="w-6 h-6 text-success" />
                <span className="font-semibold text-xs text-text-primary">Zero-Noise Proofs</span>
                <span className="text-[10px] text-text-muted">Re-verified findings with live PoCs</span>
              </div>
            </div>

            <div className="flex justify-end pt-4">
              <Button onClick={() => setStep(2)} className="bg-accent hover:bg-accent-hover">
                Get Started
              </Button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-6">
            <div className="space-y-2">
              <h2 className="text-xl font-bold text-text-primary">Target Authorization</h2>
              <p className="text-text-secondary text-sm">
                Enter your target domain or URL to launch your baseline security assessment.
              </p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-1">Target URL</label>
                <input 
                  type="url" 
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://example.com" 
                  className="w-full bg-surface-2 border border-border-subtle rounded-md px-4 py-3 text-text-primary focus:outline-none focus:border-accent"
                  required
                />
              </div>
              
              <div className="bg-warning/10 border border-warning/20 rounded-md p-4 flex items-start gap-3">
                <Shield className="w-5 h-5 text-warning shrink-0 mt-0.5" />
                <p className="text-xs text-warning/90 leading-relaxed">
                  By clicking &quot;Start Assessment&quot;, I confirm that I have explicit authorization to perform 
                  security testing on this target. I agree to the AihaX terms of service.
                </p>
              </div>
            </div>

            <div className="pt-4 flex justify-between">
              <Button variant="secondary" onClick={() => setStep(1)}>Back</Button>
              <Button 
                onClick={handleStart} 
                loading={loading} 
                disabled={!target}
                className="bg-accent hover:bg-accent-hover"
              >
                Start Assessment
              </Button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
