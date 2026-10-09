const fs = require('fs');
const path = require('path');
const { app, dialog } = require('electron');
const { autoUpdater } = require('electron-updater');
const log = require('electron-log');
const yaml = require('js-yaml');
const { getUpdateReadiness } = require('./update-policy');

autoUpdater.logger = log;
autoUpdater.logger.transports.file.level = 'info';
autoUpdater.autoDownload = false;
autoUpdater.autoInstallOnAppQuit = false;
autoUpdater.allowPrerelease = false;
autoUpdater.allowDowngrade = false;

function readPackagedUpdateConfig() {
  const configPath = path.join(process.resourcesPath, 'app-update.yml');
  if (!fs.existsSync(configPath)) return null;
  return yaml.load(fs.readFileSync(configPath, 'utf8'));
}

function setupUpdater(mainWindow, runtimeApp = app) {
  if (!runtimeApp.isPackaged || process.platform !== 'win32') {
    const readiness = getUpdateReadiness({
      isPackaged: runtimeApp.isPackaged,
      platform: process.platform,
      config: null,
    });
    log.info(readiness.reason);
    return false;
  }

  let config;
  try {
    config = readPackagedUpdateConfig();
  } catch (error) {
    log.error('Update configuration could not be read:', error.message);
    return false;
  }

  const readiness = getUpdateReadiness({
    isPackaged: runtimeApp.isPackaged,
    platform: process.platform,
    config,
  });
  if (!readiness.enabled) {
    log.info(readiness.reason);
    return false;
  }

  autoUpdater.on('checking-for-update', () => {
    log.info('Checking for signed AihaX updates.');
  });

  autoUpdater.on('update-available', async (info) => {
    log.info(`Signed update ${info.version} is available.`);
    const { response } = await dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'AihaX Update Available',
      message: `Version ${info.version} is available.`,
      detail: 'Download and install the verified update now?',
      buttons: ['Download Update', 'Later'],
      defaultId: 0,
      cancelId: 1,
    });
    if (response === 0) {
      try {
        await autoUpdater.downloadUpdate();
      } catch (error) {
        log.error('Verified update download failed:', error.message);
      }
    }
  });

  autoUpdater.on('update-not-available', (info) => {
    log.info(`AihaX is current at version ${info.version}.`);
  });

  autoUpdater.on('error', (error) => {
    log.error('Secure update check failed:', error.message);
  });

  autoUpdater.on('download-progress', (progress) => {
    log.info(
      `Update download progress ${Math.floor(progress.percent)}% ` +
        `(${progress.transferred}/${progress.total} bytes).`
    );
  });

  autoUpdater.on('update-downloaded', async (info) => {
    const { response } = await dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'AihaX Update Ready',
      message: `Version ${info.version} has been verified and downloaded.`,
      detail: 'Restart AihaX to install the update?',
      buttons: ['Restart and Install', 'Later'],
      defaultId: 0,
      cancelId: 1,
    });
    if (response === 0) autoUpdater.quitAndInstall(false, true);
  });

  autoUpdater.checkForUpdates().catch((error) => {
    log.error('Secure update check failed:', error.message);
  });
  return true;
}

module.exports = { setupUpdater, readPackagedUpdateConfig };
