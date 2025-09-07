// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // === CÁC HÀM CHUNG ===
  openDirectory: () => ipcRenderer.invoke('dialog:openDirectory'),
  runCommand: (command) => ipcRenderer.send('run-command', command),
  onCommandReply: (callback) => ipcRenderer.on('command-reply', (_event, value) => callback(value)),

  // --- Backup directory shared state ---
getBackupDir: () => ipcRenderer.invoke('backup:get-dir'),
setBackupDir: (dir) => ipcRenderer.send('backup:set-dir', dir),
onBackupDirUpdated: (cb) => {
  const handler = (_e, dir) => cb && cb(dir);
  ipcRenderer.on('backup:dir-updated', handler);
  return () => ipcRenderer.off('backup:dir-updated', handler); // optional: hủy đăng ký
},

  // === CÁC HÀM CHO CỬA SỔ CHÍNH ===
  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),
  resizeWindow: (size) => ipcRenderer.invoke('resize-window', size),
  openSettingsWindow: () => ipcRenderer.send('open-settings-window'),
  openNetworkWindow: () => ipcRenderer.send('open-network-window'),
  openBloatwareWindow: () => ipcRenderer.send('open-bloatware-window'),

  // === CÁC HÀM CHO CỬA SỔ SETTINGS ===
  getAllSettings: () => ipcRenderer.invoke('get-all-settings'),
  setToggleStatus: (data) => ipcRenderer.invoke('set-toggle-status', data),
  setPowerMode: (data) => ipcRenderer.invoke('set-power-mode', data),
  setTimeouts: (data) => ipcRenderer.invoke('set-timeout', data),
  setComputerName: (name) => ipcRenderer.invoke('set-computer-name', name),
  setWorkgroup: (name) => ipcRenderer.invoke('set-workgroup', name),
  setTimezone: (tz) => ipcRenderer.invoke('set-timezone', tz),

  // === CÁC HÀM CHO CỬA SỔ NETWORK ===
  getNetworkAdapters: () => ipcRenderer.invoke('get-network-adapters'),
  getAdapterDetails:  (ifIndex) => ipcRenderer.invoke('get-adapter-details', ifIndex),
  setAdapterState:    (payload)  => ipcRenderer.invoke('set-adapter-state', payload),
setStaticIp:  (data)  => ipcRenderer.invoke('set-static-ip', data),
setDynamicIp: (idx)   => ipcRenderer.invoke('set-dynamic-ip', idx),
  setIpv6State: (data) => ipcRenderer.invoke('set-ipv6-state', data),
  setNetworkProfile: (data) => ipcRenderer.invoke('set-network-profile', data),
  setSharingOption: (data) => ipcRenderer.invoke('set-sharing-option', data),
  
  // === CÁC HÀM CHO BLOATWARE ===
  removeBloatware: (packageNames) => ipcRenderer.invoke('remove-bloatware', packageNames),
  getInstalledApps: () => ipcRenderer.invoke('get-installed-apps'),
  getInstalledWin32: () => ipcRenderer.invoke('get-installed-win32'),

  // preload.js (thêm vào contextBridge.exposeInMainWorld)
openBitLockerWindow: () => ipcRenderer.send('open-bitlocker-window'),

isAdmin: () => ipcRenderer.invoke('bitlocker:is-admin'),
scanBitLocker: () => ipcRenderer.invoke('bitlocker:scan'),
backupBitLockerKeys: (payload) => ipcRenderer.invoke('bitlocker:backup', payload),   // { drives: ['C:','D:'], outputDir: 'D:\\BB_Backup\\Keys' }
disableBitLocker: (drives) => ipcRenderer.invoke('bitlocker:disable', drives),       // ['C:','D:']

getBackupDir: () => ipcRenderer.invoke('backup:get-dir'),
onBackupDirUpdated: (cb) => {
  const handler = (_e, dir) => cb && cb(dir);
  ipcRenderer.on('backup:dir-updated', handler);
  return () => ipcRenderer.off('backup:dir-updated', handler); // optional: hủy lắng nghe
},

// === CỬA SỔ KÍCH HOẠT (Activation) ===
openActivationWindow: () => ipcRenderer.send('open-activation-window'),
getActivationStatus: () => ipcRenderer.invoke('activation:get-status'), // -> { windows: {...}, office: [...] }
runActivation: (payload) => ipcRenderer.invoke('activation:run', payload), 


  // === WIFI BACKUP ===
  listWifiProfiles: () => ipcRenderer.invoke('wifi:list-profiles'),
  backupWifiProfiles: (payload) => ipcRenderer.invoke('wifi:backup', payload),

  // === DRIVERS BACKUP ===
  listDrivers: () => ipcRenderer.invoke('drivers:list'),
  backupDrivers: (payload) => ipcRenderer.invoke('drivers:backup', payload),

  // === BACKUP DATA ===
  getBackupDataRoots: () => ipcRenderer.invoke('backupdata:getRoots'),
  listBackupChildren: (payload) => ipcRenderer.invoke('backupdata:listChildren', payload),
  backupData: (payload) => ipcRenderer.invoke('backupdata:backup', payload), // <-- tên kênh

  // === BACKUP ZALO ===
  backupZalo: (payload) => ipcRenderer.invoke('zalo:backup', payload),

    // === BACKUP REGISTRY ===
backupRegistry:    (payload) => ipcRenderer.invoke('registry:backup', payload),
registryList: () => ipcRenderer.invoke('registry:list'),
registryZipEntries: (payload) => ipcRenderer.invoke('registry:zip-entries', payload),

  // === RESTORE ===
restoreList: (payload) => ipcRenderer.invoke('restore:list', payload),
restoreRun:  (payload) => ipcRenderer.invoke('restore:run',  payload),
});