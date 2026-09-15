const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aihax', {
  openFileDialog: () => ipcRenderer.invoke('open-file-dialog'),
  openFolder: (path) => ipcRenderer.invoke('open-folder', path),
  getPaths: () => ipcRenderer.invoke('get-paths'),
  // Auth & OS Secure Storage Bridges
  storeRefreshToken: (token) => ipcRenderer.invoke('auth:store-refresh-token', token),
  getRefreshToken: () => ipcRenderer.invoke('auth:get-refresh-token'),
  clearRefreshToken: () => ipcRenderer.invoke('auth:clear-refresh-token'),
  startOAuth: (clientId) => ipcRenderer.invoke('auth:start-oauth', clientId),
  
  // App Shell Bridges
  getSystemInfo: () => ({ platform: process.platform, arch: process.arch }),
  onDeepLink: (callback) => {
    ipcRenderer.on('deep-link', (event, url) => callback(url));
  },
  showNotification: (title, body) => {
    if (Notification.permission === 'granted') {
      new Notification(title, { body });
    } else if (Notification.permission !== 'denied') {
      Notification.requestPermission().then(permission => {
        if (permission === 'granted') new Notification(title, { body });
      });
    }
  }
});
