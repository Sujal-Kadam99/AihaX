const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');

const { getUpdateReadiness } = require('../update-policy');

const secureConfig = {
  provider: 'generic',
  url: 'https://updates.example.test/aihax',
  publisherName: ['CN=AihaX Test Signing, O=AihaX'],
};

test('development builds never enable automatic updates', () => {
  const readiness = getUpdateReadiness({
    isPackaged: false,
    platform: 'win32',
    config: secureConfig,
  });
  assert.equal(readiness.enabled, false);
  assert.match(readiness.reason, /development/);
});

test('only the packaged Windows release updater is supported', () => {
  const readiness = getUpdateReadiness({
    isPackaged: true,
    platform: 'darwin',
    config: secureConfig,
  });
  assert.equal(readiness.enabled, false);
  assert.match(readiness.reason, /Windows/);
});

test('the feed must be configured and use credential-free HTTPS', () => {
  for (const config of [
    null,
    { ...secureConfig, url: 'http://updates.example.test/aihax' },
    { ...secureConfig, url: 'https://user:secret@updates.example.test/aihax' },
    { ...secureConfig, url: 'https://updates.example.test/aihax?token=x' },
  ]) {
    const readiness = getUpdateReadiness({
      isPackaged: true,
      platform: 'win32',
      config,
    });
    assert.equal(readiness.enabled, false);
  }
});

test('a publisher allowlist is mandatory before Windows updates can run', () => {
  const readiness = getUpdateReadiness({
    isPackaged: true,
    platform: 'win32',
    config: { ...secureConfig, publisherName: undefined },
  });
  assert.equal(readiness.enabled, false);
  assert.match(readiness.reason, /publisher/);
});

test('packaged Windows updates accept only the validated feed and signer', () => {
  const readiness = getUpdateReadiness({
    isPackaged: true,
    platform: 'win32',
    config: secureConfig,
  });
  assert.equal(readiness.enabled, true);
  assert.equal(readiness.feedUrl, secureConfig.url);
  assert.deepEqual(readiness.publisherNames, secureConfig.publisherName);
});

test('release packaging refuses to run without signing and update configuration', () => {
  const script = path.join(__dirname, '..', 'scripts', 'build-release.js');
  const result = spawnSync(process.execPath, [script], {
    cwd: path.join(__dirname, '..'),
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      AIHAX_RELEASE_BUILD: '1',
    },
    encoding: 'utf8',
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /AIHAX_UPDATE_PUBLISHER/);
  assert.doesNotMatch(result.stderr, /CSC_KEY_PASSWORD=/);
});

test('signed release configuration emits its HTTPS feed and publisher allowlist', () => {
  const configPath = path.join(__dirname, '..', 'electron-builder.config.js');
  const probe = [
    'const config = require(process.argv[1]);',
    'if (config.win.sign === false) process.exit(2);',
    'if (config.win.publisherName?.[0] !== "CN=AihaX Test Signing, O=AihaX") process.exit(3);',
    'if (config.publish?.[0]?.url !== "https://updates.example.test/aihax") process.exit(4);',
  ].join('\n');
  const result = spawnSync(process.execPath, ['-e', probe, configPath], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      AIHAX_RELEASE_BUILD: '1',
      AIHAX_UPDATE_PUBLISHER: 'CN=AihaX Test Signing, O=AihaX',
      AIHAX_UPDATE_URL: 'https://updates.example.test/aihax',
      CSC_LINK: 'test-certificate.pfx',
    },
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
});
