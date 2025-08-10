const CryptoJS = require("crypto-js");
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const Store = require('electron-store');
const fs = require('fs');
const os = require('os');
const S3Sync = require('./s3_sync.js');

// Initialize stores
const passwordStore = new Store({
  name: 'syncpass_password_store',
  defaults: {}
});

// Debug: Log store path and initial contents
console.log('Password store path:', passwordStore.path);
console.log('Initial store contents:', passwordStore.store);

const settingsPath = path.join(os.homedir(), '.syncpass-settings.yml');

// Settings manager for YAML file
class SettingsManager {
  constructor() {
    this.defaultSettings = {
      autoLockTimeout: '30',
      showPasswordStrength: false,
      clipboardAutoClear: true,
      darkMode: false,
      password_set: false,
      s3AccessKey: '',
      s3SecretKey: '',
      s3BucketName: '',
      s3Region: 'us-east-1'
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
    yaml += `\n# Amazon S3 Backup Configuration\n`;
    yaml += `s3AccessKey: "${settings.s3AccessKey || ''}"\n`;
    yaml += `s3SecretKey: "${settings.s3SecretKey || ''}"\n`;
    yaml += `s3BucketName: "${settings.s3BucketName || ''}"\n`;
    yaml += `s3Region: "${settings.s3Region || 'us-east-1'}"\n`;
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
        } else if (['autoLockTimeout', 's3AccessKey', 's3SecretKey', 's3BucketName', 's3Region'].includes(key)) {
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

// Store S3 settings in main process memory (not in window)
let s3Settings = {
  accessKey: '',
  secretKey: '',
  bucketName: '',
  region: 'us-east-1'
};

// SECURITY: ALWAYS clear any plain passwords on startup - force encryption only
function clearPlainPasswordsOnStartup() {
  const settings = settingsManager.loadSettings();
  const hasEncryptedPasswords = passwordStore.has('passwords_encrypted');
  const hasPlainPasswords = passwordStore.has('passwords');
  
  console.log('=== SECURITY STARTUP PASSWORD CLEANUP ===');
  console.log('Settings password_set:', settings.password_set);
  console.log('Has encrypted passwords:', hasEncryptedPasswords);
  console.log('Has plain passwords:', hasPlainPasswords);
  
  // SECURITY: ALWAYS clear plain passwords on startup - force encryption only
  if (hasPlainPasswords) {
    console.log('SECURITY: Clearing ALL plain passwords on startup for maximum security');
    passwordStore.delete('passwords');
    
    // Force the store to persist the cleanup immediately
    try {
      if (hasEncryptedPasswords) {
        passwordStore.store = { passwords_encrypted: passwordStore.get('passwords_encrypted') };
        console.log('SECURITY: Forced cleanup - only encrypted data persists');
      } else {
        passwordStore.store = {};
        console.log('SECURITY: Forced cleanup - no passwords persist unencrypted');
      }
    } catch (error) {
      console.error('Failed to force store cleanup:', error);
    }
    
    console.log('SECURITY: All plain passwords cleared from startup');
  }
  
  // Fix the password_set setting if encrypted passwords exist
  if (hasEncryptedPasswords && !settings.password_set) {
    console.log('Fixing password_set setting - encrypted passwords exist');
    settings.password_set = true;
    settingsManager.saveSettings(settings);
  }
  
  if (!hasEncryptedPasswords && !hasPlainPasswords) {
    console.log('SECURITY: Clean state - no passwords found');
  }
  
  // ALWAYS clear session master password on startup for security
  sessionMasterPassword = null;
}

// Call cleanup on startup
clearPlainPasswordsOnStartup();

// Load S3 settings into memory on startup
function loadS3SettingsIntoMemory() {
  const settings = settingsManager.loadSettings();
  s3Settings.accessKey = settings.s3AccessKey || '';
  s3Settings.secretKey = settings.s3SecretKey || '';
  s3Settings.bucketName = settings.s3BucketName || '';
  s3Settings.region = settings.s3Region || 'us-east-1';
  console.log('S3 settings loaded into main process memory');
}

// Load S3 settings on startup
loadS3SettingsIntoMemory();

// IPC handlers for password operations
ipcMain.handle('get-passwords', () => {
  const settings = settingsManager.loadSettings();
  const hasEncryptedPasswords = passwordStore.has('passwords_encrypted');
  const hasPlainPasswords = passwordStore.has('passwords');
  
  console.log('=== GET PASSWORDS REQUEST ===');
  console.log('Settings password_set:', settings.password_set);
  console.log('Has encrypted passwords:', hasEncryptedPasswords);
  console.log('Has plain passwords:', hasPlainPasswords);
  console.log('Session master password available:', !!sessionMasterPassword);
  
  // If encrypted passwords exist, ALWAYS require unlock - regardless of settings
  if (hasEncryptedPasswords) {
    if (hasPlainPasswords && sessionMasterPassword) {
      // Passwords are temporarily decrypted in memory AND we have valid session
      console.log('Returning temporarily decrypted passwords (valid session)');
      return passwordStore.get('passwords');
    } else {
      // Passwords are locked or no valid session, return empty array
      console.log('Passwords are locked or no valid session, returning empty array');
      return [];
    }
  }
  
  // No encrypted passwords exist, return normal passwords
  console.log('No encrypted passwords exist, returning normal passwords');
  const passwords = passwordStore.get('passwords');
  
  // If no passwords exist at all, return empty array - no welcome passwords for security
  if (!passwords || passwords.length === 0) {
    console.log('No passwords found - returning empty array for security');
    return [];
  }
  
  return passwords;
});

ipcMain.handle('set-passwords', (event, passwords) => {
  console.log('Setting passwords - SECURITY: Only in memory, never unencrypted to disk');
  
  // SECURITY: NEVER save unencrypted passwords to disk
  // Only keep in memory temporarily and ONLY save encrypted version
  if (!sessionMasterPassword) {
    console.error('SECURITY: Cannot set passwords without master password session');
    return { success: false, error: 'Master password required' };
  }

  try {
    // Encrypt immediately and save only encrypted version
    const passwordsJson = JSON.stringify(passwords);
    const encryptedPasswords = CryptoJS.AES.encrypt(passwordsJson, sessionMasterPassword).toString();
    passwordStore.set('passwords_encrypted', encryptedPasswords);
    
    // Keep in memory ONLY for current session
    passwordStore.set('passwords', passwords);
    
    console.log('SECURITY: Passwords encrypted and saved securely');
    return { success: true };
  } catch (error) {
    console.error('Failed to encrypt and save passwords:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('add-password', (event, passwordData) => {
  console.log('Adding password - SECURITY: Requires encryption');
  
  if (!sessionMasterPassword) {
    console.error('SECURITY: Cannot add password without master password session');
    return { success: false, error: 'Master password required' };
  }
  
  const passwords = passwordStore.get('passwords') || [];
  
  console.log('Current passwords before add:', passwords.length);
  // Handle case where this is the first password
  const newId = passwords.length > 0 ? Math.max(...passwords.map(p => p.id)) + 1 : 1;
  const newPassword = { id: newId, ...passwordData };
  passwords.push(newPassword);
  
  try {
    // SECURITY: Always encrypt before saving
    const passwordsJson = JSON.stringify(passwords);
    const encryptedPasswords = CryptoJS.AES.encrypt(passwordsJson, sessionMasterPassword).toString();
    passwordStore.set('passwords_encrypted', encryptedPasswords);
    
    // Keep in memory ONLY for current session
    passwordStore.set('passwords', passwords);
    
    console.log('SECURITY: Password added and encrypted');
    return { success: true, password: newPassword };
  } catch (error) {
    console.error('Failed to encrypt password:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('update-password', (event, id, updatedData) => {
  console.log('Updating password ID:', id, '- SECURITY: Requires encryption');
  
  if (!sessionMasterPassword) {
    console.error('SECURITY: Cannot update password without master password session');
    return { success: false, error: 'Master password required' };
  }
  
  const passwords = passwordStore.get('passwords');
  
  if (!passwords) {
    console.error('No passwords in memory - cannot update password');
    return { success: false, error: 'No passwords loaded' };
  }
  
  const passwordIndex = passwords.findIndex(p => p.id === id);
  if (passwordIndex !== -1) {
    passwords[passwordIndex] = { ...passwords[passwordIndex], ...updatedData };
    
    try {
      // SECURITY: Always encrypt before saving
      const passwordsJson = JSON.stringify(passwords);
      const encryptedPasswords = CryptoJS.AES.encrypt(passwordsJson, sessionMasterPassword).toString();
      passwordStore.set('passwords_encrypted', encryptedPasswords);
      
      // Keep in memory ONLY for current session
      passwordStore.set('passwords', passwords);
      
      console.log('SECURITY: Password updated and encrypted');
      return { success: true, password: passwords[passwordIndex] };
    } catch (error) {
      console.error('Failed to encrypt updated password:', error);
      return { success: false, error: error.message };
    }
  }
  console.log('Password not found for update');
  return { success: false, error: 'Password not found' };
});

ipcMain.handle('delete-password', (event, id) => {
  console.log('Deleting password ID:', id, '- SECURITY: Requires encryption');
  
  if (!sessionMasterPassword) {
    console.error('SECURITY: Cannot delete password without master password session');
    return { success: false, error: 'Master password required' };
  }
  
  const passwords = passwordStore.get('passwords');
  
  if (!passwords) {
    console.error('No passwords in memory - cannot delete password');
    return { success: false, error: 'No passwords loaded' };
  }
  
  const index = passwords.findIndex(p => p.id === id);
  if (index !== -1) {
    const deleted = passwords.splice(index, 1)[0];
    
    try {
      // SECURITY: Always encrypt before saving
      const passwordsJson = JSON.stringify(passwords);
      const encryptedPasswords = CryptoJS.AES.encrypt(passwordsJson, sessionMasterPassword).toString();
      passwordStore.set('passwords_encrypted', encryptedPasswords);
      
      // Keep in memory ONLY for current session
      passwordStore.set('passwords', passwords);
      
      console.log('SECURITY: Password deleted and encrypted');
      return { success: true, deleted: deleted };
    } catch (error) {
      console.error('Failed to encrypt after password deletion:', error);
      return { success: false, error: error.message };
    }
  }
  console.log('Password not found for deletion');
  return { success: false, error: 'Password not found' };
});

// IPC handlers for settings operations
ipcMain.handle('get-settings', () => {
  return settingsManager.loadSettings();
});

ipcMain.handle('save-settings', (event, settings) => {
  const result = settingsManager.saveSettings(settings);
  
  // Update S3 settings in main process memory when settings are saved
  if (result) {
    s3Settings.accessKey = settings.s3AccessKey || '';
    s3Settings.secretKey = settings.s3SecretKey || '';
    s3Settings.bucketName = settings.s3BucketName || '';
    s3Settings.region = settings.s3Region || 'us-east-1';
    console.log('S3 settings updated in main process memory');
  }
  
  return result;
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
    
    // Store the encrypted passwords (keep plain passwords in memory for now)
    passwordStore.set('passwords_encrypted', encryptedPasswords);
    
    // Update settings to indicate password is set
    const settings = settingsManager.loadSettings();
    settings.password_set = true;
    settingsManager.saveSettings(settings);
    
    // Store master password in session memory for future operations
    sessionMasterPassword = masterPassword;
    
    console.log('Master password set successfully, passwords encrypted and session established');
    return { success: true };
  } catch (error) {
    console.error('Failed to set master password:', error);
    return { success: false, error: error.message };
  }
});

// IPC handler for unlocking with master password
ipcMain.handle('unlock-with-master-password', async (event, masterPassword) => {
  try {
    console.log('=== UNLOCK WITH MASTER PASSWORD ATTEMPT ===');
    
    // Check what we have in the store
    const encryptedPasswords = passwordStore.get('passwords_encrypted');
    const plainPasswords = passwordStore.get('passwords');
    const settings = settingsManager.loadSettings();
    
    console.log('Has encrypted passwords:', !!encryptedPasswords);
    console.log('Has plain passwords:', !!plainPasswords);
    console.log('Settings password_set:', settings.password_set);
    
    let passwordsToDecrypt = encryptedPasswords;
    
    // If we have encrypted passwords, try to decrypt them
    if (encryptedPasswords) {
      console.log('Found encrypted passwords, attempting to decrypt');
    } else if (plainPasswords && plainPasswords.length > 0) {
      // If no encrypted passwords but we have plain passwords, encrypt them first
      console.log('No encrypted passwords found, but plain passwords exist - encrypting them with provided password');
      
      const passwordsJson = JSON.stringify(plainPasswords);
      passwordsToDecrypt = CryptoJS.AES.encrypt(passwordsJson, masterPassword).toString();
      
      // Save encrypted version
      passwordStore.set('passwords_encrypted', passwordsToDecrypt);
      
      // Update settings to indicate password is now set
      settings.password_set = true;
      settingsManager.saveSettings(settings);
      
      console.log('Plain passwords encrypted and saved');
    } else {
      // No passwords at all - this should redirect to main app like a fresh install
      console.log('No passwords found - treating as fresh install');
      return { success: true, redirect: 'index.html', passwords: [] };
    }
    
    // Attempt to decrypt the passwords
    console.log('Attempting to decrypt passwords');
    const decrypted = CryptoJS.AES.decrypt(passwordsToDecrypt, masterPassword);
    const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
    
    if (!decryptedText) {
      throw new Error('Invalid master password - decryption failed');
    }
    
    let passwords;
    try {
      passwords = JSON.parse(decryptedText);
    } catch (parseError) {
      throw new Error('Invalid master password - corrupted decrypted data');
    }
    
    // Store decrypted passwords temporarily in memory
    passwordStore.set('passwords', passwords);
    
    // Store master password in session memory for re-encryption operations
    sessionMasterPassword = masterPassword;
    
    console.log('Passwords unlocked successfully, session established');
    console.log('Unlocked', passwords.length, 'passwords');
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
    
    // Store the re-encrypted passwords with new password
    passwordStore.set('passwords_encrypted', encryptedPasswords);
    
    // Re-store the passwords in memory for current session
    passwordStore.set('passwords', currentPasswords);
    
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
    
    console.log('=== CHECK PASSWORD DATA ===');
    console.log('Has encrypted passwords:', hasEncryptedPasswords);
    console.log('Has plain passwords:', hasPlainPasswords);
    console.log('Session master password available:', !!sessionMasterPassword);
    
    // Fix password_set setting if encrypted passwords exist but setting is wrong
    let actualPasswordSet = settings.password_set;
    if (hasEncryptedPasswords && !settings.password_set) {
      console.log('Fixing password_set setting - encrypted passwords exist');
      actualPasswordSet = true;
      const updatedSettings = { ...settings, password_set: true };
      settingsManager.saveSettings(updatedSettings);
    }
    
    // If we have encrypted passwords, check if they are currently unlocked
    if (hasEncryptedPasswords) {
      if (hasPlainPasswords && sessionMasterPassword) {
        // Passwords are currently unlocked and we have session key
        console.log('Passwords are currently unlocked - allowing access');
        return {
          success: true,
          password_set: actualPasswordSet,
          has_encrypted: hasEncryptedPasswords,
          has_plain: hasPlainPasswords,
          needs_password: false // Don't need password - already unlocked
        };
      } else {
        // Passwords are locked or session expired
        console.log('Passwords are locked - need unlock');
        return {
          success: true,
          password_set: actualPasswordSet,
          has_encrypted: hasEncryptedPasswords,
          has_plain: hasPlainPasswords,
          needs_password: true // Need password
        };
      }
    } else {
      // No encrypted passwords exist
      return {
        success: true,
        password_set: actualPasswordSet,
        has_encrypted: hasEncryptedPasswords,
        has_plain: hasPlainPasswords,
        needs_password: false // No password needed
      };
    }
  } catch (error) {
    console.error('Failed to check password data:', error);
    return { success: false, error: error.message };
  }
});

// IPC handler for S3 sync - ONLY syncs encrypted data for security
ipcMain.handle('sync-to-s3', async () => {
  try {
    console.log('=== S3 ENCRYPTED SYNC REQUESTED ===');
    
    // Validate S3 settings
    if (!s3Settings.accessKey || !s3Settings.secretKey || !s3Settings.bucketName) {
      throw new Error('S3 configuration incomplete. Please check your settings: Access Key, Secret Key, and Bucket Name are required.');
    }
    
    // Check if we have any passwords locally (encrypted or in memory)
    const currentPasswords = passwordStore.get('passwords');
    const hasEncryptedPasswords = passwordStore.has('passwords_encrypted');
    const hasAnyPasswords = (currentPasswords && currentPasswords.length > 0) || hasEncryptedPasswords;
    
    // If NO passwords found locally, try to download from S3 instead
    if (!hasAnyPasswords) {
      console.log('No local passwords found - attempting to download from S3 instead');
      
      try {
        // Create S3Sync instance with settings from memory
        const s3Sync = new S3Sync(s3Settings.region, s3Settings.accessKey, s3Settings.secretKey);
        const objectKey = 'syncpass_encrypted_backup.json';
        
        // Create temporary file for download
        const tempPath = path.join(os.tmpdir(), 'syncpass_download_backup.json');
        
        console.log('Downloading encrypted backup from S3 bucket:', s3Settings.bucketName);
        
        // Download the backup file
        await s3Sync.downloadFile(s3Settings.bucketName, objectKey, tempPath);
        
        // Read and parse the backup
        const backupContent = fs.readFileSync(tempPath, 'utf8');
        const backup = JSON.parse(backupContent);
        
        // Clean up temporary file
        try {
          fs.unlinkSync(tempPath);
        } catch (cleanupError) {
          console.error('Failed to clean up temporary file:', cleanupError);
        }
        
        // Validate backup structure
        if (!backup.encrypted_passwords) {
          throw new Error('Invalid backup file: missing encrypted passwords');
        }
        
        // Check if the encrypted backup actually contains passwords by trying to decrypt a test
        // We can't fully decrypt without the password, but we can check if it's empty
        const encryptedData = backup.encrypted_passwords;
        
        // Store the encrypted passwords locally
        passwordStore.set('passwords_encrypted', encryptedData);
        
        // Update settings to indicate password is set
        const settings = settingsManager.loadSettings();
        settings.password_set = true;
        settingsManager.saveSettings(settings);
        
        console.log('Downloaded encrypted backup successfully');
        
        // Always redirect to unlock screen since we have encrypted data that needs to be unlocked
        return { 
          success: true, 
          result: 'downloaded',
          message: 'Encrypted backup downloaded from S3.',
          redirect_to_unlock: true
        };
      } catch (downloadError) {
        console.error('Failed to download from S3:', downloadError);
        
        // If no backup exists on S3, that's normal for a fresh install - go to main screen
        if (downloadError.message && downloadError.message.includes('NoSuchKey')) {
          console.log('No backup found on S3 - normal for fresh install');
          return {
            success: true,
            result: 'no_backup_found',
            message: 'No backup found on S3. Starting fresh.',
            redirect_to_main: true
          };
        }
        
        return {
          success: false,
          error: `No local passwords found and failed to download from S3: ${downloadError.message}`
        };
      }
    }
    
    // If we have current passwords in memory but no encrypted version and we have a session password
    if (currentPasswords && currentPasswords.length > 0 && !hasEncryptedPasswords && sessionMasterPassword) {
      console.log('Encrypting current passwords before backup');
      const passwordsJson = JSON.stringify(currentPasswords);
      const encryptedPasswords = CryptoJS.AES.encrypt(passwordsJson, sessionMasterPassword).toString();
      passwordStore.set('passwords_encrypted', encryptedPasswords);
      
      // Update settings to indicate password is set
      const settings = settingsManager.loadSettings();
      settings.password_set = true;
      settingsManager.saveSettings(settings);
    }
    
    // Check if we have encrypted passwords to backup
    const encryptedPasswords = passwordStore.get('passwords_encrypted');
    if (!encryptedPasswords) {
      throw new Error('No encrypted passwords found. Please set a master password first before backing up.');
    }
    
    console.log('S3 settings validated, attempting encrypted sync to bucket:', s3Settings.bucketName);
    
    // Create secure backup object with only encrypted data
    const secureBackup = {
      encrypted_passwords: encryptedPasswords
    };
    
    // Save encrypted backup to a persistent file that can be synced
    const backupPath = path.join(os.homedir(), '.syncpass_encrypted_backup.json');
    fs.writeFileSync(backupPath, JSON.stringify(secureBackup, null, 2), 'utf8');
    
    console.log('Saved encrypted backup file:', backupPath);
    
    // Create S3Sync instance with settings from memory
    const s3Sync = new S3Sync(s3Settings.region, s3Settings.accessKey, s3Settings.secretKey);
    
    const objectKey = 'syncpass_encrypted_backup.json';
    
    console.log('Syncing encrypted backup to S3 bucket:', s3Settings.bucketName);
    console.log('S3 object key:', objectKey);
    
    const syncResult = await s3Sync.syncFile(backupPath, s3Settings.bucketName, objectKey);
    
    console.log('Encrypted sync completed with result:', syncResult);
    
    return { 
      success: true, 
      result: syncResult,
      message: `Encrypted backup ${syncResult}`
    };
  } catch (error) {
    console.error('S3 encrypted sync failed:', error);
    return { 
      success: false, 
      error: error.message 
    };
  }
});

// IPC handler for restoring from S3 backup - ONLY loads encrypted data for security
ipcMain.handle('restore-from-s3', async () => {
  try {
    console.log('=== S3 ENCRYPTED RESTORE REQUESTED ===');
    
    // Validate S3 settings
    if (!s3Settings.accessKey || !s3Settings.secretKey || !s3Settings.bucketName) {
      throw new Error('S3 configuration incomplete. Please check your settings: Access Key, Secret Key, and Bucket Name are required.');
    }
    
    console.log('S3 settings validated, attempting restore from bucket:', s3Settings.bucketName);
    
    // Create temporary file for download
    const tempPath = path.join(os.tmpdir(), 'syncpass_restore_backup.json');
    
    try {
      // Create S3Sync instance with settings from memory
      const s3Sync = new S3Sync(s3Settings.region, s3Settings.accessKey, s3Settings.secretKey);
      
      const objectKey = 'syncpass_encrypted_backup.json';
      
      console.log('Downloading encrypted backup from S3 bucket:', s3Settings.bucketName);
      console.log('S3 object key:', objectKey);
      
      // Download the backup file
      await s3Sync.downloadFile(s3Settings.bucketName, objectKey, tempPath);
      
      // Read and parse the backup
      const backupContent = fs.readFileSync(tempPath, 'utf8');
      const backup = JSON.parse(backupContent);
      
      // Validate backup structure
      if (!backup.encrypted_passwords) {
        throw new Error('Invalid backup file: missing encrypted passwords');
      }
      
      // Store the encrypted passwords (replacing any existing ones)
      passwordStore.set('passwords_encrypted', backup.encrypted_passwords);
      
      // Clear any unencrypted passwords from memory for security
      if (passwordStore.has('passwords')) {
        passwordStore.delete('passwords');
        console.log('Cleared any unencrypted passwords from memory for security');
      }
      
      // Update settings to indicate password is set
      const settings = settingsManager.loadSettings();
      settings.password_set = true;
      settingsManager.saveSettings(settings);
      
      // Clear session master password to force re-authentication
      sessionMasterPassword = null;
      
      console.log('Encrypted backup restored successfully');
      
      return { 
        success: true, 
        message: 'Encrypted backup restored successfully. Please unlock with your master password.',
        backup_timestamp: backup.backup_timestamp || 'Unknown'
      };
    } finally {
      // Clean up temporary file
      try {
        if (fs.existsSync(tempPath)) {
          fs.unlinkSync(tempPath);
          console.log('Cleaned up temporary restore file');
        }
      } catch (cleanupError) {
        console.error('Failed to clean up temporary file:', cleanupError);
      }
    }
  } catch (error) {
    console.error('S3 encrypted restore failed:', error);
    return { 
      success: false, 
      error: error.message 
    };
  }
});

// IPC handler for clearing passwords from memory (lock function)
ipcMain.handle('lock-passwords', () => {
  try {
    console.log('=== LOCKING PASSWORDS ===');
    
    const currentPasswords = passwordStore.get('passwords');
    const hasEncryptedPasswords = passwordStore.has('passwords_encrypted');
    
    console.log('Current passwords count:', currentPasswords ? currentPasswords.length : 0);
    console.log('Has encrypted passwords:', hasEncryptedPasswords);
    console.log('Session master password available:', !!sessionMasterPassword);
    
    // If we have passwords but no encrypted version and no session master password,
    // we need to prompt for master password to encrypt them
    if (currentPasswords && currentPasswords.length > 0 && !hasEncryptedPasswords && !sessionMasterPassword) {
      console.log('Passwords exist but no encryption setup - need master password');
      return { 
        success: false, 
        error: 'master_password_required',
        message: 'Master password required to encrypt passwords before locking'
      };
    }
    
    // If we have session master password, save current passwords as encrypted
    if (currentPasswords && currentPasswords.length > 0 && sessionMasterPassword) {
      console.log('Saving current passwords as encrypted before lock');
      try {
        const passwordsJson = JSON.stringify(currentPasswords);
        const encryptedPasswords = CryptoJS.AES.encrypt(passwordsJson, sessionMasterPassword).toString();
        passwordStore.set('passwords_encrypted', encryptedPasswords);
        console.log('Current passwords saved as encrypted');
        
        // Update settings to indicate password is set
        const settings = settingsManager.loadSettings();
        if (!settings.password_set) {
          settings.password_set = true;
          settingsManager.saveSettings(settings);
          console.log('Updated settings to indicate master password is set');
        }
      } catch (encryptError) {
        console.error('Failed to save encrypted passwords on lock:', encryptError);
        return { success: false, error: 'Failed to encrypt passwords: ' + encryptError.message };
      }
    }
    
    // Clear temporary passwords from memory
    if (passwordStore.has('passwords')) {
      passwordStore.delete('passwords');
      console.log('Temporary passwords cleared from memory');
    }
    
    // Clear session master password
    sessionMasterPassword = null;
    console.log('Session master password cleared');
    
    // Verify encrypted passwords are still on disk
    const hasEncrypted = passwordStore.has('passwords_encrypted');
    console.log('Encrypted passwords still on disk:', hasEncrypted);
    
    console.log('Lock completed - encrypted data saved, temporary data cleared');
    return { success: true };
  } catch (error) {
    console.error('Failed to lock passwords:', error);
    return { success: false, error: error.message };
  }
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1000,
    height: 800,
    title: 'SyncPass',
    icon: path.join(__dirname, 'icon.svg'),
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  // ALWAYS start with lock screen for maximum security
  const settings = settingsManager.loadSettings();
  const hasEncryptedPasswords = passwordStore.has('passwords_encrypted');
  const hasPlainPasswords = passwordStore.has('passwords');
  
  console.log('=== STARTUP DECISION LOGIC ===');
  console.log('Settings password_set:', settings.password_set);
  console.log('Has encrypted passwords:', hasEncryptedPasswords);
  console.log('Has plain passwords:', hasPlainPasswords);
  console.log('ALWAYS starting with lock screen for security');
  
  // Clear any unencrypted passwords on startup for security if encrypted passwords exist
  if (hasEncryptedPasswords && hasPlainPasswords) {
    console.log('Clearing unencrypted passwords on startup for security');
    passwordStore.delete('passwords');
    
    // Force the store to save immediately - only keep encrypted data
    try {
      passwordStore.store = { passwords_encrypted: passwordStore.get('passwords_encrypted') };
      console.log('Forced cleanup of password store - only encrypted data remains');
    } catch (error) {
      console.error('Failed to force cleanup store:', error);
    }
  }
  
  // ALWAYS clear session master password on startup for security
  sessionMasterPassword = null;
  console.log('Cleared session master password on startup');
  
  // Ensure password_set is true if we have encrypted passwords
  if (hasEncryptedPasswords && !settings.password_set) {
    console.log('Fixing password_set setting - encrypted passwords exist');
    settings.password_set = true;
    settingsManager.saveSettings(settings);
  }
  
  // ALWAYS start with unlock screen for maximum security
  win.loadFile('unlock.html');
  
  // Clear any temporarily decrypted passwords when window is closed
  win.on('closed', () => {
    const settings = settingsManager.loadSettings();
    if (settings.password_set) {
      console.log('Window closed - clearing any temporary passwords from memory');
      passwordStore.delete('passwords');
      sessionMasterPassword = null;
    }
  });
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
      // SECURITY: NEVER save unencrypted passwords - require encryption first
      console.log('SECURITY: Cannot save unencrypted passwords - user must set master password first');
      passwordStore.delete('passwords');
      console.log('SECURITY: Cleared unencrypted passwords for security');
    } else if (!settings.password_set && (!hasPlainPasswords || !currentPasswords)) {
      console.log('SECURITY: No passwords to save - clean state');
    }
    
    // SECURITY: If master password is set, NEVER save plain passwords to disk
    if (settings.password_set && hasEncryptedPasswords) {
      console.log('SECURITY: Ensuring no plain passwords are saved to disk when master password is set');
      if (passwordStore.has('passwords')) {
        passwordStore.delete('passwords');
        console.log('Removed any plain passwords from persistent storage for security');
      }
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
