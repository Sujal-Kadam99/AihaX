import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Combines dynamic class names safely using clsx and resolves Tailwind CSS class conflicts.
 * @param {...any} inputs - Class names or conditional class objects.
 * @returns {string} Merged class string.
 */
export function cn(...inputs) {
  return twMerge(clsx(inputs));
}
