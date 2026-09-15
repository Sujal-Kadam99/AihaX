import React from 'react';
import Button from './Button';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    // Log safe diagnostic information without exposing secrets
    console.error('ErrorBoundary caught a render exception:', error?.message || error, errorInfo?.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return typeof this.props.fallback === 'function'
          ? this.props.fallback({ error: this.state.error, reset: this.handleReset })
          : this.props.fallback;
      }

      return (
        <div
          role="alert"
          data-testid="error-boundary-fallback"
          className="p-6 max-w-xl mx-auto my-8 rounded-lg bg-surface border border-critical/30 space-y-4 shadow-sm"
        >
          <div className="flex items-center gap-2.5 text-critical font-semibold text-sm">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" aria-hidden="true" focusable="false" />
            <span>Configuration Interface Recovery</span>
          </div>

          <p className="text-xs text-text-secondary leading-relaxed">
            An unexpected error occurred while rendering the assessment interface. Security boundaries and execution gates remain intact.
          </p>

          {this.state.error?.message && (
            <div className="p-2.5 rounded bg-surface-2 border border-border text-[11px] font-mono text-text-muted break-all">
              {this.state.error.message}
            </div>
          )}

          <div className="pt-2 flex items-center gap-3">
            <Button
              variant="secondary"
              size="sm"
              onClick={this.handleReset}
              className="flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" focusable="false" />
              <span>Reset View</span>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.reload()}
            >
              Reload Page
            </Button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
