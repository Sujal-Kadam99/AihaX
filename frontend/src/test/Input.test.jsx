import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import Input from '../components/ui/Input';

describe('Input Primitive', () => {
  it('renders label and handles value changes', () => {
    render(<Input label="Target URL" placeholder="https://example.com" />);
    expect(screen.getByLabelText('Target URL')).toBeDefined();
  });

  it('renders error message and sets aria-invalid', () => {
    render(<Input label="Target URL" error="Invalid URL format" />);
    const input = screen.getByLabelText('Target URL');
    expect(input.getAttribute('aria-invalid')).toBe('true');
    expect(screen.getByRole('alert').textContent).toBe('Invalid URL format');
  });
});
