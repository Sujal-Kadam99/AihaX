import { describe, it, expect } from 'vitest';
import { validateConcreteTargetUrl } from '../utils/urlValidator';

describe('Frontend Concrete Target URL Validator', () => {
  it('accepts valid HTTPS target URLs', () => {
    const res = validateConcreteTargetUrl('https://example.com');
    expect(res.valid).toBe(true);
    expect(res.host).toBe('example.com');
  });

  it('accepts valid HTTP target URLs', () => {
    const res = validateConcreteTargetUrl('http://example.com');
    expect(res.valid).toBe(true);
    expect(res.host).toBe('example.com');
  });

  it('accepts valid subdomain and path target URLs', () => {
    const res = validateConcreteTargetUrl('https://example-shop.myshopify.com/store/checkout');
    expect(res.valid).toBe(true);
    expect(res.host).toBe('example-shop.myshopify.com');
  });

  it('rejects empty string and whitespace', () => {
    expect(validateConcreteTargetUrl('').valid).toBe(false);
    expect(validateConcreteTargetUrl('   ').valid).toBe(false);
    expect(validateConcreteTargetUrl(null).valid).toBe(false);
  });

  it('rejects bare hostnames without scheme', () => {
    const res = validateConcreteTargetUrl('example.com');
    expect(res.valid).toBe(false);
    expect(res.error).toContain('must start with http:// or https://');
  });

  it('rejects wildcard hostnames', () => {
    const res = validateConcreteTargetUrl('*.shopify.com');
    expect(res.valid).toBe(false);
    expect(res.error).toContain('Wildcard scope rules cannot be used');
  });

  it('rejects wildcard URLs', () => {
    const res = validateConcreteTargetUrl('https://*.shopify.com');
    expect(res.valid).toBe(false);
    expect(res.error).toContain('Wildcard scope rules cannot be used');
  });

  it('rejects javascript: scheme', () => {
    const res = validateConcreteTargetUrl('javascript:alert(1)');
    expect(res.valid).toBe(false);
  });

  it('rejects data: scheme', () => {
    const res = validateConcreteTargetUrl('data:text/html,<h1>Test</h1>');
    expect(res.valid).toBe(false);
  });

  it('rejects file: scheme', () => {
    const res = validateConcreteTargetUrl('file:///etc/passwd');
    expect(res.valid).toBe(false);
  });

  it('rejects mailto: scheme', () => {
    const res = validateConcreteTargetUrl('mailto:admin@example.com');
    expect(res.valid).toBe(false);
  });

  it('rejects userinfo / credential URLs', () => {
    const res = validateConcreteTargetUrl('https://admin:secret@evil.com');
    expect(res.valid).toBe(false);
    expect(res.error).toContain('credentials');
  });

  it('rejects invalid ports', () => {
    const res = validateConcreteTargetUrl('https://example.com:99999');
    expect(res.valid).toBe(false);
    expect(res.error).toBeDefined();
  });
});
