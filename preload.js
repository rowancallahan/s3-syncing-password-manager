const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // Password operations
  getPasswords: () => ipcRenderer.invoke('get-passwords'),
  setPasswords: (passwords) => ipcRenderer.invoke('set-passwords', passwords),
  addPassword: (passwordData) => ipcRenderer.invoke('add-password', passwordData),
  updatePassword: (id, updatedData) => ipcRenderer.invoke('update-password', id, updatedData),
  deletePassword: (id) => ipcRenderer.invoke('delete-password', id),
  
  // Settings operations
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),
  
  // File operations
  saveToDesktop: (filename, content) => ipcRenderer.invoke('save-to-desktop', filename, content),
  
  // Encryption operations
  encryptData: (data, password) => ipcRenderer.invoke('encrypt-data', data, password),
  decryptData: (encryptedData, password) => ipcRenderer.invoke('decrypt-data', encryptedData, password),
  
  // Master password operations
  setMasterPassword: (masterPassword) => ipcRenderer.invoke('set-master-password', masterPassword),
  unlockWithMasterPassword: (masterPassword) => ipcRenderer.invoke('unlock-with-master-password', masterPassword),
  resetMasterPassword: (newMasterPassword) => ipcRenderer.invoke('reset-master-password', newMasterPassword),
  checkPasswordData: () => ipcRenderer.invoke('check-password-data'),
  lockPasswords: () => ipcRenderer.invoke('lock-passwords'),
  
  // S3 sync operations
  syncToS3: () => ipcRenderer.invoke('sync-to-s3'),
  restoreFromS3: () => ipcRenderer.invoke('restore-from-s3')
});