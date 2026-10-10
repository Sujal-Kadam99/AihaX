/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: 'var(--color-bg-app)',
        surface: 'var(--color-bg-surface)',
        'surface-2': 'var(--color-bg-surface-elevated)',
        'surface-hover': 'var(--color-bg-surface-hover)',
        border: 'var(--color-border-default)',
        'border-subtle': 'var(--color-border-subtle)',
        'border-strong': 'var(--color-border-strong)',
        accent: 'var(--color-brand-accent)',
        'accent-hover': 'var(--color-brand-accent-hover)',
        'text-primary': 'var(--color-text-primary)',
        'text-secondary': 'var(--color-text-secondary)',
        'text-muted': 'var(--color-text-muted)',
        critical: 'var(--color-critical)',
        'critical-bg': 'var(--color-critical-bg)',
        high: 'var(--color-high)',
        'high-bg': 'var(--color-high-bg)',
        medium: 'var(--color-medium)',
        'medium-bg': 'var(--color-medium-bg)',
        low: 'var(--color-low)',
        'low-bg': 'var(--color-low-bg)',
        info: 'var(--color-info)',
        'info-bg': 'var(--color-info-bg)',
        warning: 'var(--color-warning)',
        'warning-bg': 'var(--color-warning-bg)',
        success: 'var(--color-success)',
        'success-bg': 'var(--color-success-bg)',
      },
      fontFamily: {
        display: ['Inter', 'sans-serif'],
        body: ['Inter', 'sans-serif'],
        code: ['"JetBrains Mono"', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '6px',
        sm: '2px',
        md: '6px',
        lg: '10px',
      },
      animation: {
        pulse: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-pulse': 'glow-pulse 2s ease-in-out infinite',
      },
      keyframes: {
        'glow-pulse': {
          '0%, 100%': { boxShadow: '0 0 5px var(--color-brand-accent-glow)' },
          '50%': { boxShadow: '0 0 20px var(--color-brand-accent-glow)' },
        },
      },
    },
  },
  plugins: [],
};
