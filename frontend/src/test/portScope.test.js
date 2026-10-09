import { describe, it, expect } from 'vitest';
import { parsePortScope } from '../lib/portScope';

describe('parsePortScope', () => {
  it('expands, sorts, and deduplicates authorized port ranges', () => {
    expect(parsePortScope('80, 8000-8002, 443, 8001')).toEqual([80, 443, 8000, 8001, 8002]);
  });

  it('rejects malformed and out-of-range port entries', () => {
    expect(() => parsePortScope('80, 70000')).toThrow(/1 through 65535/);
    expect(() => parsePortScope('80, 8002-8000')).toThrow(/range/);
    expect(() => parsePortScope('80, nope')).toThrow(/Invalid port/);
  });
});
