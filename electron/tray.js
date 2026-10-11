const { app, Menu, Tray, nativeImage } = require('electron');
const path = require('path');

let tray = null;

function createTray(mainWindow) {
  if (tray) return tray;

  // Ideally, use a real icon. Using a fallback empty icon for now if not found.
  let iconPath = path.join(__dirname, '..', 'build', 'icon.png');
  let trayIcon = nativeImage.createFromPath(iconPath);
  if (trayIcon.isEmpty()) {
      // Fallback empty transparent icon
      trayIcon = nativeImage.createEmpty();
  }
  
  trayIcon = trayIcon.resize({ width: 16, height: 16 });
  
  tray = new Tray(trayIcon);
  tray.setToolTip('AihaX - Automated Penetration Testing');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Open AihaX',
      click: () => {
        if (mainWindow) {
          if (mainWindow.isMinimized()) mainWindow.restore();
          mainWindow.show();
          mainWindow.focus();
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Status: Healthy',
      enabled: false,
      id: 'status-item'
    },
    { type: 'separator' },
    {
      label: 'Quit AihaX',
      click: () => {
        app.isQuiting = true;
        app.quit();
      }
    }
  ]);

  tray.setContextMenu(contextMenu);

  tray.on('click', () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) {
        if (mainWindow.isFocused()) {
          mainWindow.hide();
        } else {
          mainWindow.focus();
        }
      } else {
        mainWindow.show();
      }
    }
  });

  return tray;
}

function updateTrayStatus(status, message) {
    if (!tray) return;
    // To properly update, we'll re-build the menu just updating the status text
    const newMenu = Menu.buildFromTemplate([
        {
          label: 'Open AihaX',
          click: () => {
              const mainWindow = global.mainWindowRef;
            if (mainWindow) {
              if (mainWindow.isMinimized()) mainWindow.restore();
              mainWindow.show();
              mainWindow.focus();
            }
          }
        },
        { type: 'separator' },
        {
          label: `Status: ${message}`,
          enabled: false,
        },
        { type: 'separator' },
        {
          label: 'Quit AihaX',
          click: () => {
            app.isQuiting = true;
            app.quit();
          }
        }
      ]);
    tray.setContextMenu(newMenu);
}


module.exports = {
  createTray,
  updateTrayStatus
};
