const { execFileSync } = require('child_process');
const path = require('path');

const missing = ['AIHAX_UPDATE_PUBLISHER', 'AIHAX_UPDATE_URL', 'CSC_LINK'].filter(
  (name) => !process.env[name]?.trim()
);
if (missing.length) {
  console.error(`Release build stopped: configure ${missing.join(', ')} first.`);
  process.exit(1);
}

let updateUrl;
try {
  updateUrl = new URL(process.env.AIHAX_UPDATE_URL);
} catch {
  console.error('Release build stopped: AIHAX_UPDATE_URL must be a valid URL.');
  process.exit(1);
}
if (updateUrl.protocol !== 'https:' || updateUrl.username || updateUrl.password) {
  console.error('Release build stopped: AIHAX_UPDATE_URL must use credential-free HTTPS.');
  process.exit(1);
}

const cwd = path.resolve(__dirname, '..');
const env = { ...process.env, AIHAX_RELEASE_BUILD: '1' };
const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const npxCommand = process.platform === 'win32' ? 'npx.cmd' : 'npx';

execFileSync(npmCommand, ['run', 'build:frontend'], { cwd, env, stdio: 'inherit' });
execFileSync(
  npxCommand,
  ['electron-builder', '--win', '--config', 'electron-builder.config.js'],
  { cwd, env, stdio: 'inherit' }
);
