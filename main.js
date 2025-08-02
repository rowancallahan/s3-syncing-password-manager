const CryptoJS = require("crypto-js");
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const Store = require('electron-store');
const fs = require('fs');
const os = require('os');

// Initialize stores
const passwordStore = new Store({
  name: 'passwords',
  defaults: {
    passwords: [
      { 
        id: 1, 
        title: 'Welcome', 
        website: 'Welcome to SyncPass', 
        username: 'demo@example.com', 
        password: 'Welcome123!' 
      }
    ]
  }
});

// Debug: Log store path and initial contents
console.log('Password store path:', passwordStore.path);
console.log('Initial store contents:', passwordStore.store);

const settingsPath = path.join(os.homedir(), '.syncpass-settings.yml');

// Settings manager for YAML file
class SettingsManager {
  constructor() {
    this.defaultSettings = {
      autoLockTimeout: '15',
      showPasswordStrength: false,
      clipboardAutoClear: true,
      darkMode: false,
      password_set: false
    };
  }
  
  loadSettings() {
    try {
      if (fs.existsSync(settingsPath)) {
        const content = fs.readFileSync(settingsPath, 'utf8');
        return this.parseYAML(content);
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
    return this.defaultSettings;
  }
  
  saveSettings(settings) {
    try {
      const yaml = this.convertToYAML(settings);
      fs.writeFileSync(settingsPath, yaml, 'utf8');
      return true;
    } catch (error) {
      console.error('Failed to save settings:', error);
      return false;
    }
  }
  
  convertToYAML(settings) {
    let yaml = '# SyncPass Settings\n';
    yaml += `autoLockTimeout: "${settings.autoLockTimeout}"\n`;
    yaml += `showPasswordStrength: ${settings.showPasswordStrength}\n`;
    yaml += `clipboardAutoClear: ${settings.clipboardAutoClear}\n`;
    yaml += `darkMode: ${settings.darkMode}\n`;
    yaml += `password_set: ${settings.password_set}\n`;
    yaml += `\n# Last updated: ${new Date().toISOString()}\n`;
    return yaml;
  }
  
  parseYAML(yaml) {
    const settings = { ...this.defaultSettings };
    const lines = yaml.split('\n');
    
    lines.forEach(line => {
      const trimmed = line.trim();
      if (trimmed.startsWith('#') || !trimmed.includes(':')) return;
      
      const [key, value] = trimmed.split(':').map(s => s.trim());
      if (key && value) {
        if (['showPasswordStrength', 'clipboardAutoClear', 'darkMode', 'password_set'].includes(key)) {
          settings[key] = value === 'true';
        } else if (key === 'autoLockTimeout') {
          settings[key] = value.replace(/"/g, '');
        }
      }
    });
    
    return settings;
  }
}

const settingsManager = new SettingsManager();

// Store master password in memory during session for re-encryption on close
let sessionMasterPassword = null;

// IPC handlers for password operations
ipcMain.handle('get-passwords', () => {
  const settings = settingsManager.loadSettings();
  const hasEncryptedPasswords = passwordStore.has('passwords_encrypted');
  const hasPlainPasswords = passwordStore.has('passwords');
  
  // If master password is set and we have encrypted data, only return passwords if they're temporarily decrypted
  if (settings.password_set && hasEncryptedPasswords) {
    if (hasPlainPasswords) {
      // Passwords are temporarily decrypted in memory
      return passwordStore.get('passwords');
    } else {
      // Passwords are locked, return empty array
      return [];
    }
  }
  
  // No master password set, return normal passwords
  return passwordStore.get('passwords') || [];
});

ipcMain.handle('set-passwords', (event, passwords) => {
  console.log('Setting passwords:', passwords);
  passwordStore.set('passwords', passwords);
  console.log('Passwords set, store now contains:', passwordStore.get('passwords'));
  return true;
});

ipcMain.handle('add-password', (event, passwordData) => {
  console.log('Adding password:', passwordData);
  const passwords = passwordStore.get('passwords');
  console.log('Current passwords before add:', passwords);
  const newId = Math.max(...passwords.map(p => p.id)) + 1;
  const newPassword = { id: newId, ...passwordData };
  passwords.push(newPassword);
  passwordStore.set('passwords', passwords);
  console.log('Passwords after add:', passwordStore.get('passwords'));
  return newPassword;
});

ipcMain.handle('update-password', (event, id, updatedData) => {
  console.log('Updating password ID:', id, 'with data:', updatedData);
  const passwords = passwordStore.get('passwords');
  const passwordIndex = passwords.findIndex(p => p.id === id);
  if (passwordIndex !== -1) {
    passwords[passwordIndex] = { ...passwords[passwordIndex], ...updatedData };
    passwordStore.set('passwords', passwords);
    console.log('Password updated, store now contains:', passwordStore.get('passwords'));
    return passwords[passwordIndex];
  }
  console.log('Password not found for update');
  return null;
});

ipcMain.handle('delete-password', (event, id) => {
  console.log('Deleting password ID:', id);
  const passwords = passwordStore.get('passwords');
  const index = passwords.findIndex(p => p.id === id);
  if (index !== -1) {
    const deleted = passwords.splice(index, 1)[0];
    passwordStore.set('passwords', passwords);
    console.log('Password deleted, store now contains:', passwordStore.get('passwords'));
    return deleted;
  }
  console.log('Password not found for deletion');
  return null;
});

// IPC handlers for settings operations
ipcMain.handle('get-settings', () => {
  return settingsManager.loadSettings();
});

ipcMain.handle('save-settings', (event, settings) => {
  return settingsManager.saveSettings(settings);
});

// IPC handler for encryption
ipcMain.handle('encrypt-data', (event, data, password) => {
  try {
    if (!password || !data) {
      throw new Error('Both data and password are required for encryption');
    }
    const encrypted = CryptoJS.AES.encrypt(data, password).toString();
    return { success: true, encrypted };
  } catch (error) {
    console.error('Encryption failed:', error);
    return { success: false, error: error.message };
  }
});

// IPC handler for decryption
ipcMain.handle('decrypt-data', (event, encryptedData, password) => {
  try {
    if (!password || !encryptedData) {
      throw new Error('Both encrypted data and password are required for decryption');
    }
    const decrypted = CryptoJS.AES.decrypt(encryptedData, password);
    const plaintext = decrypted.toString(CryptoJS.enc.Utf8);
    
    if (!plaintext) {
      throw new Error('Invalid password or corrupted data');
    }
    
    return { success: true, decrypted: plaintext };
  } catch (error) {
    console.error('Decryption failed:', error);
    return { success: false, error: error.message };
  }
});

// IPC handler for saving encrypted file to desktop
ipcMain.handle('save-to-desktop', (event, filename, content) => {
  try {
    const desktopPath = path.join(os.homedir(), 'Desktop');
    const filePath = path.join(desktopPath, filename);
    
    fs.writeFileSync(filePath, content, 'utf8');
    return { success: true, path: filePath };
  } catch (error) {
    console.error('Failed to save file to desktop:', error);
    return { success: false, error: error.message };
  }
});

// IPC handler for setting master password
ipcMain.handle('set-master-password', async (event, masterPassword) => {
  try {
    // Get current passwords (either from memory or from store)
    const currentPasswords = passwordStore.get('passwords');
    
    if (!currentPasswords || currentPasswords.length === 0) {
      throw new Error('No passwords found to encrypt');
    }
    
    // Encrypt the password data
    const passwordsJson = JSON.stringify(currentPasswords);
    const encryptedPasswords = CryptoJS.AES.encrypt(passwordsJson, masterPassword).toString();
    
    // Clear the store completely first
    passwordStore.clear();
    
    // Store only the encrypted passwords
    passwordStore.set('passwords_encrypted', encryptedPasswords);
    
    // Update settings to indicate password is set
    const settings = settingsManager.loadSettings();
    settings.password_set = true;
    settingsManager.saveSettings(settings);
    
    // Store master password in session memory for re-encryption on close
    sessionMasterPassword = masterPassword;
    
    console.log('Master password set successfully, all password data encrypted and unencrypted data removed');
    return { success: true };
  } catch (error) {
    console.error('Failed to set master password:', error);
    return { success: false, error: error.message };
  }
});

// IPC handler for unlocking with master password
ipcMain.handle('unlock-with-master-password', async (event, masterPassword) => {
  try {
    const encryptedPasswords = passwordStore.get('passwords_encrypted');
    
    if (!encryptedPasswords) {
      throw new Error('No encrypted passwords found');
    }
    
    // Decrypt passwords
    const decrypted = CryptoJS.AES.decrypt(encryptedPasswords, masterPassword);
    const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
    
    if (!decryptedText) {
      throw new Error('Invalid master password');
    }
    
    const passwords = JSON.parse(decryptedText);
    
    // Temporarily store decrypted passwords in memory
    passwordStore.set('passwords', passwords);
    
    // Store master password in session memory for re-encryption on close
    sessionMasterPassword = masterPassword;
    
    return { success: true, passwords };
  } catch (error) {
    console.error('Failed to unlock with master password:', error);
    return { success: false, error: error.message };
  }
});

// IPC handler for resetting master password (when passwords are in memory)
ipcMain.handle('reset-master-password', async (event, newMasterPassword) => {
  try {
    // Check if passwords are currently available in memory
    const currentPasswords = passwordStore.get('passwords');
    
    if (!currentPasswords || currentPasswords.length === 0) {
      throw new Error('No passwords in memory. Please unlock first before resetting password.');
    }
    
    // Encrypt with new password
    const passwordsJson = JSON.stringify(currentPasswords);
    const encryptedPasswords = CryptoJS.AES.encrypt(passwordsJson, newMasterPassword).toString();
    
    // Clear the store completely first
    passwordStore.clear();
    
    // Store only the encrypted passwords with new password
    passwordStore.set('passwords_encrypted', encryptedPasswords);
    
    // Ensure settings still show password is set
    const settings = settingsManager.loadSettings();
    settings.password_set = true;
    settingsManager.saveSettings(settings);
    
    // Update session master password
    sessionMasterPassword = newMasterPassword;
    
    console.log('Master password reset successfully, all password data re-encrypted');
    return { success: true };
  } catch (error) {
    console.error('Failed to reset master password:', error);
    return { success: false, error: error.message };
  }
});

// IPC handler for checking if passwords can be loaded without password
ipcMain.handle('check-password-data', () => {
  try {
    const settings = settingsManager.loadSettings();
    const hasEncryptedPasswords = passwordStore.has('passwords_encrypted');
    const hasPlainPasswords = passwordStore.has('passwords');
    
    // If master password is set, clear any temporarily decrypted passwords on startup
    if (settings.password_set && hasEncryptedPasswords && hasPlainPasswords) {
      console.log('Clearing temporary decrypted passwords on startup');
      passwordStore.delete('passwords');
    }
    
    // Recalculate after potential cleanup
    const hasPlainPasswordsAfterCleanup = passwordStore.has('passwords');
    
    return {
      success: true,
      password_set: settings.password_set,
      has_encrypted: hasEncryptedPasswords,
      has_plain: hasPlainPasswordsAfterCleanup,
      needs_password: settings.password_set && hasEncryptedPasswords
    };
  } catch (error) {
    console.error('Failed to check password data:', error);
    return { success: false, error: error.message };
  }
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1000,
    height: 800,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  win.loadFile('index.html');
}

app.whenReady().then(createWindow);

// Save passwords and manage storage when app is closing
app.on('before-quit', (event) => {
  event.preventDefault(); // Prevent immediate quit
  
  setTimeout(() => {
    app.exit(); // Force quit after delay
  }, 500); // Give 500ms for file operations to complete
  try {
    const settings = settingsManager.loadSettings();
    const hasEncryptedPasswords = passwordStore.has('passwords_encrypted');
    const hasPlainPasswords = passwordStore.has('passwords');
    const currentPasswords = passwordStore.get('passwords');
    
    console.log('=== APP CLOSING - MANAGING PASSWORD STORAGE ===');
    console.log('Settings:', settings);
    console.log('Has encrypted passwords:', hasEncryptedPasswords);
    console.log('Has plain passwords:', hasPlainPasswords);
    console.log('Current passwords count:', currentPasswords ? currentPasswords.length : 0);
    console.log('Session master password available:', !!sessionMasterPassword);
    
    if (settings.password_set && hasEncryptedPasswords) {
      // Master password is set - need to handle encrypted storage
      if (hasPlainPasswords && currentPasswords && currentPasswords.length > 0 && sessionMasterPassword) {
        // There are passwords in memory that need to be saved and we have the session master password
        console.log('Re-encrypting and saving passwords with master password before app close');
        
        try {
          // Encrypt the current passwords with the session master password
          const passwordsJson = JSON.stringify(currentPasswords);
          const encryptedPasswords = CryptoJS.AES.encrypt(passwordsJson, sessionMasterPassword).toString();
          
          // Update the encrypted storage
          passwordStore.set('passwords_encrypted', encryptedPasswords);
          console.log('Encrypted passwords saved to store');
          
          // Clear temporary plain passwords
          passwordStore.delete('passwords');
          console.log('Temporary plain passwords cleared');
          
          console.log('Successfully saved encrypted passwords on app close');
        } catch (encryptError) {
          console.error('Failed to encrypt passwords on close:', encryptError);
          // Keep the existing encrypted version as fallback
        }
      } else if (hasPlainPasswords && currentPasswords && currentPasswords.length > 0) {
        console.log('Master password set but no session password available - clearing temporary passwords');
        passwordStore.delete('passwords');
      } else {
        console.log('No plain passwords to process - encrypted storage should already exist');
      }
    } else if (!settings.password_set && hasPlainPasswords && currentPasswords) {
      // No master password set - save passwords normally to persistent storage
      console.log('No master password - ensuring passwords are saved to persistent storage');
      console.log('Saving passwords:', currentPasswords);
      passwordStore.set('passwords', currentPasswords);
      console.log('Passwords saved to store, verification:', passwordStore.get('passwords'));
    } else if (!settings.password_set && (!hasPlainPasswords || !currentPasswords)) {
      console.log('No master password set and no current passwords - using defaults');
      // Ensure defaults are set
      const defaultPasswords = [
        { 
          id: 1, 
          title: 'Welcome', 
          website: 'Welcome to SyncPass', 
          username: 'demo@example.com', 
          password: 'Welcome123!' 
        }
      ];
      passwordStore.set('passwords', defaultPasswords);
      console.log('Default passwords set');
    }
    
    // Force store to flush to disk
    try {
      console.log('Final store contents before quit:', passwordStore.store);
    } catch (storeError) {
      console.error('Error reading final store contents:', storeError);
    }
    
    // Clear session master password from memory
    sessionMasterPassword = null;
    
    console.log('=== PASSWORD STORAGE MANAGEMENT COMPLETED ===');
  } catch (error) {
    console.error('Error managing passwords on app quit:', error);
  }
});
