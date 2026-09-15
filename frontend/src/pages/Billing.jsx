import { useEffect, useState } from 'react';
import { ShoppingCart, CheckCircle2 } from 'lucide-react';
import { createCheckoutSession, getBillingPlans } from '../lib/api';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import Alert from '../components/ui/Alert';
import Skeleton from '../components/ui/Skeleton';

const PLANS = [
  {
    id: 'pro_monthly',
    name: 'Pro',
    price: '$29/month',
    description: 'Unlimited scans, full auth, full report, learning',
  },
  {
    id: 'pro_one_time',
    name: 'Pro One-time',
    price: '$79 one-time',
    description: 'Unlimited scans, full auth, full report, learning',
  },
  {
    id: 'team',
    name: 'Team',
    price: '$99/month',
    description: '5 seats, shared learning DB, white-label reports',
  },
  {
    id: 'agency',
    name: 'Agency',
    price: '$299/month',
    description: 'Unlimited seats, client-branded reports, priority support',
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: '$999/month',
    description: 'Self-hosted, custom deployment, SLA',
  },
];

export default function Billing() {
  const [plans, setPlans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');

  useEffect(() => {
    getBillingPlans()
      .then((res) => {
        setPlans(res.data.plans || PLANS);
        setLoading(false);
      })
      .catch(() => {
        setPlans(PLANS);
        setLoading(false);
      });
  }, []);

  const handleSubscribe = async (plan) => {
    if (!plan.id) {
      setMessage('No Stripe price configured for this plan. Set price IDs in Settings first.');
      return;
    }

    setLoading(true);
    try {
      const hostname = window.location.origin;
      const successUrl = `${hostname}/`;
      const cancelUrl = `${hostname}/settings`;
      const payload = {
        price_id: plan.id,
        success_url: successUrl,
        cancel_url: cancelUrl,
      };
      const res = await createCheckoutSession(payload);
      if (res.data?.url) {
        window.location.assign(res.data.url);
      } else {
        setMessage('Unable to start checkout.');
      }
    } catch (err) {
      setMessage(err.response?.data?.detail || 'Checkout failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <ShoppingCart className="w-6 h-6 text-accent" />
        <div>
          <h1 className="font-display text-2xl font-bold text-text-primary">Billing & Plans</h1>
          <p className="text-text-secondary text-sm">
            Choose a plan and complete checkout with Stripe.
          </p>
        </div>
      </div>

      {message && <Alert variant="warning">{message}</Alert>}

      {loading ? (
        <div className="grid gap-4 md:grid-cols-2">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-36 w-full" />
          ))}
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {plans.map((plan) => (
            <Card key={plan.id} variant="interactive" className="flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between gap-4">
                  <h2 className="font-semibold text-text-primary text-base">{plan.name}</h2>
                  <span className="text-lg font-bold font-display text-accent">{plan.price}</span>
                </div>
                <p className="text-xs text-text-secondary mt-2">{plan.description}</p>
              </div>
              <Button
                variant="primary"
                size="sm"
                startIcon={CheckCircle2}
                disabled={!plan.id || loading}
                onClick={() => handleSubscribe(plan)}
                className="mt-6 w-full"
              >
                Subscribe
              </Button>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
