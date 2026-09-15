const path = require('path');
const fs = require('fs');

const electronRoot = path.resolve(__dirname, '../electron');
const electronModuleDir = path.join(electronRoot, 'node_modules/electron');

// Add paths to require resolution
module.paths.unshift(
  path.join(electronRoot, 'node_modules'),
  path.join(electronModuleDir, 'node_modules')
);

const { downloadArtifact } = require('@electron/get');
const extract = require('extract-zip');

async function main() {
  const electronPkgPath = path.join(electronModuleDir, 'package.json');
  const version = JSON.parse(fs.readFileSync(electronPkgPath, 'utf-8')).version;
  console.log(`Target Electron Version: ${version}`);

  const zipPath = await downloadArtifact({
    version,
    artifactName: 'electron',
    platform: 'win32',
    arch: 'x64',
  });
  console.log(`Zip downloaded to: ${zipPath}`);

  const distDir = path.join(electronModuleDir, 'dist');
  fs.mkdirSync(distDir, { recursive: true });
  console.log(`Extracting to: ${distDir}`);
  await extract(zipPath, { dir: distDir });

  const pathFile = path.join(electronModuleDir, 'path.txt');
  fs.writeFileSync(pathFile, 'electron.exe', 'utf-8');

  const exePath = path.join(distDir, 'electron.exe');
  console.log(`Electron installed successfully! Exists: ${fs.existsSync(exePath)}`);
}

main().catch((err) => {
  console.error('Error during setup:', err);
  process.exit(1);
});
