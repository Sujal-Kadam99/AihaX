const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aihax', {
  openFileDialog: () => ipcRenderer.invoke('open-file-dialog'),
  openFolder: (path) => ipcRenderer.invoke('open-folder', path),
  getPaths: () => ipcRenderer.invoke('get-paths'),
  // Auth & OS Secure Storage Bridges
  storeRefreshToken: (token) => ipcRenderer.invoke('auth:store-refresh-token', token),
  getRefreshToken: () => ipcRenderer.invoke('auth:get-refresh-token'),
  clearRefreshToken: () => ipcRenderer.invoke('auth:clear-refresh-token'),
  startOAuth: () => ipcRenderer.invoke('auth:start-oauth'),
  
  // App Shell Bridges
  getSystemInfo: () => ({ platform: process.platform, arch: process.arch }),
  onDeepLink: (callback) => {
    const listener = (_event, url) => callback(url);
    ipcRenderer.on('deep-link', listener);
    return () => ipcRenderer.removeListener('deep-link', listener);
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
