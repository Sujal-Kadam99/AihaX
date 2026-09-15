const { app, BrowserWindow, ipcMain, dialog, shell, safeStorage, crashReporter, session } = require('electron');
const { exec, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const os = require('os');
const { createTray, updateTrayStatus } = require('./tray');
const { setupUpdater } = require('./updater');

// Setup Crash Reporter
crashReporter.start({
  productName: 'AihaX',
  companyName: 'AihaX',
  submitURL: 'https://aihax.test/api/crashes',
  uploadToServer: false, // Disabled until Cloud phase
});

const API_URL = 'http://localhost:8000';
const FRONTEND_DEV_URL = 'http://localhost:3000';
const HEALTH_TIMEOUT = 60000;
const HEALTH_POLL_INTERVAL = 2000;

let mainWindow = null;
let dockerProcess = null;

// Deep link protocol registration
if (process.defaultApp) {
  if (process.argv.length >= 2) {
    app.setAsDefaultProtocolClient('aihax', process.execPath, [path.resolve(process.argv[1])]);
  }
} else {
  app.setAsDefaultProtocolClient('aihax');
}

function getAihaXPaths() {
  const home = process.env.USERPROFILE || os.homedir();
  return {
    reports: path.join(home, 'AihaX', 'Reports').replace(/\\/g, '/'),
    db: path.join(home, 'AihaX', 'db').replace(/\\/g, '/'),
    config: path.join(home, 'AihaX', 'config').replace(/\\/g, '/'),
  };
}

function checkDockerRunning() {
  return new Promise((resolve) => {
    exec('docker info', { timeout: 10000 }, (error) => {
      resolve(!error);
    });
  });
}

function getResourcePath(resourceSubPath) {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, resourceSubPath);
  }
  return path.join(__dirname, '..', resourceSubPath);
}

function startDockerCompose() {
  return new Promise((resolve, reject) => {
    const paths = getAihaXPaths();
    const composePath = path.join(getResourcePath('docker'), 'docker-compose.yml');
    const env = {
      ...process.env,
      AIHAX_REPORTS: paths.reports,
      AIHAX_DB: paths.db,
      AIHAX_CONFIG: paths.config,
    };

    dockerProcess = spawn('docker', ['compose', '-f', composePath, 'up', '-d'], {
      env,
      shell: true,
      cwd: getResourcePath('docker'),
    });

    dockerProcess.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`docker-compose exited with code ${code}`));
    });

    dockerProcess.on('error', reject);
  });
}

async function waitForHealth() {
  const start = Date.now();
  while (Date.now() - start < HEALTH_TIMEOUT) {
    try {
      const response = await axios.get(`${API_URL}/api/health`, { timeout: 3000 });
      if (response.data.status === 'ok') return true;
    } catch {
      // Backend not ready yet
    }
    await new Promise((r) => setTimeout(r, HEALTH_POLL_INTERVAL));
  }
  return false;
}

function createWindow() {
  const paths = getAihaXPaths();
  const windowStatePath = path.join(paths.config, 'window-state.json');
  let windowState = { width: 1400, height: 900, x: undefined, y: undefined };
  
  if (fs.existsSync(windowStatePath)) {
      try {
          windowState = JSON.parse(fs.readFileSync(windowStatePath, 'utf-8'));
      } catch (e) {
          // ignore
      }
  }

  mainWindow = new BrowserWindow({
    width: windowState.width,
    height: windowState.height,
    x: windowState.x,
    y: windowState.y,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#0D1117',
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0D1117',
      symbolColor: '#E6EDF3',
      height: 40,
    },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // Strict CSP Headers
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self' 'unsafe-inline' 'unsafe-eval' http://localhost:8000 http://localhost:3000 wss://localhost:3000 ws://localhost:3000; img-src 'self' data: https:;"]
      }
    });
  });

  global.mainWindowRef = mainWindow;

  if (app.isPackaged) {
    mainWindow.loadFile(path.join(__dirname, '..', 'frontend', 'dist', 'index.html'));
  } else {
    mainWindow.loadURL(FRONTEND_DEV_URL);
  }

  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
  }

  // Save window state
  mainWindow.on('close', () => {
    const bounds = mainWindow.getBounds();
    fs.mkdirSync(paths.config, { recursive: true });
    fs.writeFileSync(windowStatePath, JSON.stringify(bounds));
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
    global.mainWindowRef = null;
  });

  // Setup Updater
  setupUpdater(mainWindow);
}

async function showDockerDialog() {
  const { response } = await dialog.showMessageBox({
    type: 'warning',
    title: 'Docker Desktop Required',
    message: 'Docker Desktop is not running.',
    detail: 'AihaX requires Docker Desktop to run security tools in an isolated container. Please start Docker Desktop and click Retry.',
    buttons: ['Retry', 'Quit'],
    defaultId: 0,
  });
  return response === 0;
}

async function showErrorDialog(message) {
  await dialog.showMessageBox({
    type: 'error',
    title: 'AihaX Startup Error',
    message,
    detail: 'Check that Docker Desktop is running and ports 8000/3000 are available.',
    buttons: ['Quit'],
  });
}

app.whenReady().then(async () => {
  let dockerRunning = await checkDockerRunning();

  while (!dockerRunning) {
    const retry = await showDockerDialog();
    if (!retry) {
      app.quit();
      return;
    }
    dockerRunning = await checkDockerRunning();
  }

  try {
    await startDockerCompose();
  } catch (err) {
    await showErrorDialog(`Failed to start Docker containers: ${err.message}`);
    app.quit();
    return;
  }

  const healthy = await waitForHealth();
  if (!healthy) {
    await showErrorDialog('Backend health check timed out after 60 seconds.');
    app.quit();
    return;
  }

  createWindow();
  createTray(mainWindow);
  updateTrayStatus('online', 'Healthy');
});

// Enforce single instance and handle deep links
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', (event, commandLine, workingDirectory) => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
    // Handle deep link logic here
    const deepLink = commandLine.find(arg => arg.startsWith('aihax://'));
    if (deepLink && mainWindow) {
        mainWindow.webContents.send('deep-link', deepLink);
    }
  });
  
  app.on('open-url', (event, url) => {
      event.preventDefault();
      if (mainWindow) {
          mainWindow.webContents.send('deep-link', url);
      }
  });
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  const composePath = path.join(getResourcePath('docker'), 'docker-compose.yml');
  exec(`docker compose -f "${composePath}" down`, { shell: true });
});

ipcMain.handle('open-file-dialog', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: [{ name: 'PDF Reports', extensions: ['pdf'] }],
  });
  return result.filePaths[0] || null;
});

ipcMain.handle('open-folder', async (_, folderPath) => {
  const paths = getAihaXPaths();
  await shell.openPath(folderPath || paths.reports);
});

ipcMain.handle('get-paths', () => getAihaXPaths());

// -----------------------------------------------------------------------------
// Security & Authentication IPC Handlers (safeStorage + System Browser PKCE)
// -----------------------------------------------------------------------------

const { startDesktopOAuthFlow } = require('./oauth');

function getSessionEncFilePath() {
  const paths = getAihaXPaths();
  return path.join(paths.config, 'session.enc');
}

ipcMain.handle('auth:store-refresh-token', async (_, refreshToken) => {
  if (!refreshToken) return false;
  try {
    const encPath = getSessionEncFilePath();
    fs.mkdirSync(path.dirname(encPath), { recursive: true });

    if (safeStorage && safeStorage.isEncryptionAvailable()) {
      const encryptedBuffer = safeStorage.encryptString(refreshToken);
      fs.writeFileSync(encPath, encryptedBuffer, { mode: 0o600 });
      return true;
    } else {
      console.warn('safeStorage encryption unavailable on this OS environment');
      return false;
    }
  } catch (err) {
    console.error('Failed to securely store refresh token');
    return false;
  }
});

ipcMain.handle('auth:get-refresh-token', async () => {
  try {
    const encPath = getSessionEncFilePath();
    if (!fs.existsSync(encPath)) return null;

    const encryptedBuffer = fs.readFileSync(encPath);
    if (safeStorage && safeStorage.isEncryptionAvailable()) {
      return safeStorage.decryptString(encryptedBuffer);
    }
    return null;
  } catch (err) {
    console.error('Failed to decrypt refresh token');
    return null;
  }
});

ipcMain.handle('auth:clear-refresh-token', async () => {
  try {
    const encPath = getSessionEncFilePath();
    if (fs.existsSync(encPath)) {
      fs.unlinkSync(encPath);
    }
    return true;
  } catch {
    return false;
  }
});

ipcMain.handle('auth:start-oauth', async (_, googleClientId) => {
  return startDesktopOAuthFlow(googleClientId);
});

