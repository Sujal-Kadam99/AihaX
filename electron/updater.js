const { autoUpdater } = require('electron-updater');
const { dialog } = require('electron');
const log = require('electron-log');

// Setup logging
autoUpdater.logger = log;
autoUpdater.logger.transports.file.level = 'info';

function setupUpdater(mainWindow) {
    autoUpdater.on('checking-for-update', () => {
        log.info('Checking for updates...');
    });
    
    autoUpdater.on('update-available', (info) => {
        log.info('Update available.');
        dialog.showMessageBox({
            type: 'info',
            title: 'Update Available',
            message: `Version ${info.version} is available. Downloading now...`
        });
    });
    
    autoUpdater.on('update-not-available', (info) => {
        log.info('Update not available.');
    });
    
    autoUpdater.on('error', (err) => {
        log.error('Error in auto-updater. ' + err);
    });
    
    autoUpdater.on('download-progress', (progressObj) => {
        let log_message = "Download speed: " + progressObj.bytesPerSecond;
        log_message = log_message + ' - Downloaded ' + progressObj.percent + '%';
        log_message = log_message + ' (' + progressObj.transferred + "/" + progressObj.total + ')';
        log.info(log_message);
    });
    
    autoUpdater.on('update-downloaded', (info) => {
        log.info('Update downloaded');
        dialog.showMessageBox({
            title: 'Install Updates',
            message: 'Updates downloaded, application will be quit for update...',
            buttons: ['Install and Relaunch']
        }).then((buttonIndex) => {
            if (buttonIndex.response === 0) {
                autoUpdater.quitAndInstall();
            }
        });
    });

    // We stub the update checking for now
    try {
        if (!process.env.DEV_MODE) {
            autoUpdater.checkForUpdatesAndNotify();
        }
    } catch (err) {
        log.error("Could not check for updates:", err);
    }
}

module.exports = {
    setupUpdater
};
