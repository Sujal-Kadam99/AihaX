const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { isPathWithin, validateDeepLink } = require('../security');

test('allows only the root or descendants of the AihaX data directory', () => {
  const root = path.resolve('C:/Users/test/AihaX');
  assert.equal(isPathWithin(root, path.join(root, 'Reports')), true);
  assert.equal(isPathWithin(root, path.resolve(root, '..', 'outside')), false);
});

test('accepts only a stateful auth callback deep link', () => {
  assert.equal(validateDeepLink('aihax://auth/callback?code=c&state=s'), 'aihax://auth/callback?code=c&state=s');
  assert.equal(validateDeepLink('https://evil.example/callback?code=c&state=s'), null);
  assert.equal(validateDeepLink('aihax://auth/other?code=c&state=s'), null);
  assert.equal(validateDeepLink('aihax://auth/callback?code=c&state=s&next=https://evil.example'), null);
});
