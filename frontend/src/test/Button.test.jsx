import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import Button from '../components/ui/Button';

describe('Button Primitive', () => {
  it('renders children correctly', () => {
    render(<Button>Click Me</Button>);
    expect(screen.getByRole('button', { name: 'Click Me' })).toBeDefined();
  });

  it('handles click events', async () => {
    const handleClick = vi.fn();
    render(<Button onClick={handleClick}>Click Me</Button>);
    await userEvent.click(screen.getByRole('button'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('disables button when isLoading is true', () => {
    render(<Button isLoading>Submit</Button>);
    const btn = screen.getByRole('button');
    expect(btn.disabled).toBe(true);
    expect(screen.getByRole('status')).toBeDefined();
  });

  it('applies focus-visible rings correctly', () => {
    render(<Button>Accessible</Button>);
    const btn = screen.getByRole('button');
    expect(btn.className).toContain('focus-visible:ring-2');
  });
});
