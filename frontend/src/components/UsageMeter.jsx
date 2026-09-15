import { Card, CardContent } from './ui/Card';
import Button from './ui/Button';
import { useNavigate } from 'react-router-dom';
import { AlertCircle, Zap } from 'lucide-react';

export default function UsageMeter({ used, limit = 3 }) {
  const navigate = useNavigate();
  const percentage = Math.min((used / limit) * 100, 100);
  const isNearLimit = used >= limit - 1;
  const isAtLimit = used >= limit;

  return (
    <Card className={`border ${isAtLimit ? 'border-destructive' : isNearLimit ? 'border-warning' : 'border-border-subtle'} bg-surface-1`}>
      <CardContent className="p-4 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex-1 w-full">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <Zap className="w-4 h-4 text-accent" />
              Community Plan Usage
            </h3>
            <span className="text-xs text-text-secondary font-medium">
              {used} / {limit} Monthly Scans
            </span>
          </div>
          <div className="h-2 w-full bg-surface-3 rounded-full overflow-hidden">
            <div 
              className={`h-full rounded-full transition-all duration-500 ${isAtLimit ? 'bg-destructive' : isNearLimit ? 'bg-warning' : 'bg-accent'}`}
              style={{ width: `${percentage}%` }}
            />
          </div>
          {isNearLimit && !isAtLimit && (
            <p className="text-xs text-warning mt-2 flex items-center gap-1">
              <AlertCircle className="w-3 h-3" /> You are nearing your monthly scan limit.
            </p>
          )}
          {isAtLimit && (
            <p className="text-xs text-destructive mt-2 flex items-center gap-1">
              <AlertCircle className="w-3 h-3" /> You have reached your monthly scan limit.
            </p>
          )}
        </div>
        
        <div className="shrink-0 w-full md:w-auto text-right">
          <Button 
            variant="primary" 
            onClick={() => navigate('/billing')}
            className="w-full md:w-auto bg-gradient-to-r from-accent to-accent-hover"
          >
            Upgrade to Pro
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
