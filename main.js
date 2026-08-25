const { app, BrowserWindow, ipcMain, safeStorage } = require('electron');
const path = require('path');
const Store = require('electron-store');
const fs = require('fs');
const os = require('os');
const S3Sync = require('./s3_sync.js');
const { encryptVault, decryptVault } = require('./vault_crypto.js');

// Persistent store: holds ONLY the encrypted vault blob and its logical
// timestamp. Plaintext passwords must never be written here.
const passwordStore = new Store({
  name: 'syncpass_password_store',
  defaults: {}
});

const settingsPath = path.join(os.homedir(), '.syncpass-settings.yml');
const S3_BACKUP_KEY = 'syncpass_encrypted_backup.json';
const MIN_MASTER_PASSWORD_LENGTH = 12;

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
      s3SecretKeyEncrypted: '',
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
    return { ...this.defaultSettings };
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
    yaml += `s3SecretKeyEncrypted: "${settings.s3SecretKeyEncrypted || ''}"\n`;
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
        } else if (['autoLockTimeout', 's3AccessKey', 's3SecretKey', 's3SecretKeyEncrypted', 's3BucketName', 's3Region'].includes(key)) {
          settings[key] = value.replace(/"/g, '');
        }
      }
    });

    return settings;
  }
}

const settingsManager = new SettingsManager();

// The decrypted vault lives ONLY in these process-memory variables while the
// app is unlocked. They are never persisted.
let sessionPasswords = null;
let sessionMasterPassword = null;

// S3 settings held in main process memory (never sent to the renderer beyond
// what the settings form needs).
let s3Settings = {
  accessKey: '',
  secretKey: '',
  bucketName: '',
  region: 'us-east-1'
};

function isUnlocked() {
  return sessionPasswords !== null && !!sessionMasterPassword;
}

function lockSession() {
  sessionPasswords = null;
  sessionMasterPassword = null;
}

// Encrypts the in-memory vault and persists only the ciphertext, stamping a
// logical modification time used by S3 sync. Reuses the existing vault salt so
// repeated saves skip the expensive key derivation; pass freshSalt=true when
// the master password changes.
function saveVault(freshSalt = false) {
  if (!isUnlocked()) {
    throw new Error('Vault is locked - master password required');
  }
  let reuseSalt = null;
  if (!freshSalt) {
    const existing = passwordStore.get('passwords_encrypted');
    if (existing) {
      try {
        const parsed = JSON.parse(existing);
        if (parsed && parsed.v === 2 && parsed.salt) reuseSalt = parsed.salt;
      } catch (e) {
        // Legacy blob: no salt to reuse.
      }
    }
  }
  const encrypted = encryptVault(JSON.stringify(sessionPasswords), sessionMasterPassword, reuseSalt);
  passwordStore.set('passwords_encrypted', encrypted);
  passwordStore.set('vault_updated_at', new Date().toISOString());

  const settings = settingsManager.loadSettings();
  if (!settings.password_set) {
    settings.password_set = true;
    settingsManager.saveSettings(settings);
  }
}

// Older versions of this app persisted decrypted passwords through
// electron-store. Scrub any such leftovers from disk once at startup.
function cleanupLegacyPlaintext() {
  if (passwordStore.has('passwords')) {
    console.log('Removing legacy plaintext password data from disk');
    passwordStore.delete('passwords');
  }
}

// --- S3 secret key handling (OS keychain via safeStorage when available) ---

function getStoredS3Secret(settings) {
  if (settings.s3SecretKeyEncrypted) {
    try {
      if (safeStorage.isEncryptionAvailable()) {
        return safeStorage.decryptString(Buffer.from(settings.s3SecretKeyEncrypted, 'base64'));
      }
      console.error('S3 secret key is keychain-encrypted but OS encryption is unavailable');
    } catch (error) {
      console.error('Failed to decrypt stored S3 secret key:', error.message);
    }
    return '';
  }
  return settings.s3SecretKey || '';
}

// Mutates `settings` so the secret is stored as safely as this OS allows.
function storeS3Secret(settings, plainSecret) {
  if (safeStorage.isEncryptionAvailable()) {
    settings.s3SecretKeyEncrypted = safeStorage.encryptString(plainSecret).toString('base64');
    settings.s3SecretKey = '';
  } else {
    console.warn('OS keychain encryption unavailable - storing S3 secret key in plaintext settings');
    settings.s3SecretKeyEncrypted = '';
    settings.s3SecretKey = plainSecret;
  }
}

function migrateS3SecretToSafeStorage() {
  try {
    const settings = settingsManager.loadSettings();
    if (settings.s3SecretKey && !settings.s3SecretKeyEncrypted && safeStorage.isEncryptionAvailable()) {
      storeS3Secret(settings, settings.s3SecretKey);
      settingsManager.saveSettings(settings);
      console.log('Migrated S3 secret key into OS-encrypted storage');
    }
  } catch (error) {
    console.error('S3 secret key migration failed:', error.message);
  }
}

function loadS3SettingsIntoMemory() {
  const settings = settingsManager.loadSettings();
  s3Settings.accessKey = settings.s3AccessKey || '';
  s3Settings.secretKey = getStoredS3Secret(settings);
  s3Settings.bucketName = settings.s3BucketName || '';
  s3Settings.region = settings.s3Region || 'us-east-1';
}

// Adopts a downloaded backup as the local vault and locks the session so the
// user must unlock with the master password that encrypted it.
function adoptRemoteBackup(remote) {
  passwordStore.set('passwords_encrypted', remote.encrypted_passwords);
  passwordStore.set('vault_updated_at', remote.vault_updated_at || new Date().toISOString());
  const settings = settingsManager.loadSettings();
  if (!settings.password_set) {
    settings.password_set = true;
    settingsManager.saveSettings(settings);
  }
  lockSession();
}

// --- IPC: password operations ---

ipcMain.handle('get-passwords', () => {
  if (isUnlocked()) {
    return sessionPasswords;
  }
  return [];
});

ipcMain.handle('set-passwords', (event, passwords) => {
  if (!isUnlocked()) {
    return { success: false, error: 'Master password required' };
  }
  if (!Array.isArray(passwords)) {
    return { success: false, error: 'Invalid password data' };
  }
  try {
    sessionPasswords = passwords;
    saveVault();
    return { success: true };
  } catch (error) {
    console.error('Failed to save passwords:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('add-password', (event, passwordData) => {
  if (!isUnlocked()) {
    return { success: false, error: 'Master password required' };
  }
  try {
    const newId = sessionPasswords.length > 0
      ? Math.max(...sessionPasswords.map(p => p.id)) + 1
      : 1;
    const newPassword = { id: newId, ...passwordData };
    sessionPasswords.push(newPassword);
    saveVault();
    return { success: true, password: newPassword };
  } catch (error) {
    console.error('Failed to add password:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('update-password', (event, id, updatedData) => {
  if (!isUnlocked()) {
    return { success: false, error: 'Master password required' };
  }
  const index = sessionPasswords.findIndex(p => p.id === id);
  if (index === -1) {
    return { success: false, error: 'Password not found' };
  }
  try {
    sessionPasswords[index] = { ...sessionPasswords[index], ...updatedData };
    saveVault();
    return { success: true, password: sessionPasswords[index] };
  } catch (error) {
    console.error('Failed to update password:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('delete-password', (event, id) => {
  if (!isUnlocked()) {
    return { success: false, error: 'Master password required' };
  }
  const index = sessionPasswords.findIndex(p => p.id === id);
  if (index === -1) {
    return { success: false, error: 'Password not found' };
  }
  try {
    const deleted = sessionPasswords.splice(index, 1)[0];
    saveVault();
    return { success: true, deleted };
  } catch (error) {
    console.error('Failed to delete password:', error);
    return { success: false, error: error.message };
  }
});

// --- IPC: settings ---

ipcMain.handle('get-settings', () => {
  const settings = settingsManager.loadSettings();
  // Never send the S3 secret to the renderer; report only whether one is set.
  return {
    autoLockTimeout: settings.autoLockTimeout,
    showPasswordStrength: settings.showPasswordStrength,
    clipboardAutoClear: settings.clipboardAutoClear,
    darkMode: settings.darkMode,
    password_set: settings.password_set,
    s3AccessKey: settings.s3AccessKey,
    s3SecretKey: '',
    s3SecretKeySet: !!(settings.s3SecretKeyEncrypted || settings.s3SecretKey),
    s3BucketName: settings.s3BucketName,
    s3Region: settings.s3Region
  };
});

ipcMain.handle('save-settings', (event, incoming) => {
  const existing = settingsManager.loadSettings();
  const settings = { ...existing, ...incoming };

  const newSecret = incoming && typeof incoming.s3SecretKey === 'string'
    ? incoming.s3SecretKey.trim()
    : '';
  if (newSecret) {
    storeS3Secret(settings, newSecret);
  } else {
    // Empty field means "keep the stored secret".
    settings.s3SecretKey = existing.s3SecretKey;
    settings.s3SecretKeyEncrypted = existing.s3SecretKeyEncrypted;
  }

  const result = settingsManager.saveSettings(settings);
  if (result) {
    s3Settings.accessKey = settings.s3AccessKey || '';
    s3Settings.secretKey = getStoredS3Secret(settings);
    s3Settings.bucketName = settings.s3BucketName || '';
    s3Settings.region = settings.s3Region || 'us-east-1';
  }
  return result;
});

// --- IPC: generic encryption (used by export/import) ---

ipcMain.handle('encrypt-data', (event, data, password) => {
  try {
    if (!password || !data) {
      throw new Error('Both data and password are required for encryption');
    }
    return { success: true, encrypted: encryptVault(data, password) };
  } catch (error) {
    console.error('Encryption failed:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('decrypt-data', (event, encryptedData, password) => {
  try {
    if (!password || !encryptedData) {
      throw new Error('Both encrypted data and password are required for decryption');
    }
    const { plaintext } = decryptVault(encryptedData, password);
    return { success: true, decrypted: plaintext };
  } catch (error) {
    console.error('Decryption failed:', error.message);
    return { success: false, error: error.message };
  }
});

// --- IPC: file export ---

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

// --- IPC: master password lifecycle ---

ipcMain.handle('set-master-password', async (event, masterPassword) => {
  try {
    if (typeof masterPassword !== 'string' || masterPassword.length < MIN_MASTER_PASSWORD_LENGTH) {
      throw new Error(`Master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters long`);
    }
    // Refuse to overwrite an existing locked vault with a new empty one.
    if (passwordStore.has('passwords_encrypted') && sessionPasswords === null) {
      throw new Error('A vault already exists - unlock it before setting a new master password');
    }
    sessionPasswords = sessionPasswords || [];
    sessionMasterPassword = masterPassword;
    saveVault(true);
    console.log('Master password set; vault encrypted');
    return { success: true };
  } catch (error) {
    console.error('Failed to set master password:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('unlock-with-master-password', async (event, masterPassword) => {
  try {
    const encrypted = passwordStore.get('passwords_encrypted');

    if (!encrypted) {
      // Fresh install: nothing to unlock.
      return { success: true, redirect: 'index.html', passwords: [] };
    }

    const { plaintext, legacy } = decryptVault(encrypted, masterPassword);

    let passwords;
    try {
      passwords = JSON.parse(plaintext);
      if (!Array.isArray(passwords)) throw new Error('not an array');
    } catch (parseError) {
      // Legacy CBC vaults have no integrity check, so a wrong password can
      // decrypt to garbage; JSON parsing is the backstop.
      throw new Error('Invalid master password - decryption failed');
    }

    sessionPasswords = passwords;
    sessionMasterPassword = masterPassword;

    if (legacy) {
      // Upgrade the stored vault to the authenticated v2 format.
      saveVault(true);
      console.log('Legacy vault migrated to authenticated format');
    }

    console.log(`Vault unlocked (${passwords.length} entries)`);
    return { success: true, passwords };
  } catch (error) {
    console.error('Failed to unlock:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('reset-master-password', async (event, newMasterPassword) => {
  try {
    if (typeof newMasterPassword !== 'string' || newMasterPassword.length < MIN_MASTER_PASSWORD_LENGTH) {
      throw new Error(`Master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters long`);
    }
    if (!isUnlocked()) {
      throw new Error('Vault is locked. Please unlock first before changing the master password.');
    }
    sessionMasterPassword = newMasterPassword;
    saveVault(true);
    console.log('Master password changed; vault re-encrypted');
    return { success: true };
  } catch (error) {
    console.error('Failed to change master password:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('check-password-data', () => {
  try {
    const settings = settingsManager.loadSettings();
    const hasEncrypted = passwordStore.has('passwords_encrypted');
    const unlocked = isUnlocked();

    // Reconcile the settings flag with reality.
    let actualPasswordSet = settings.password_set;
    if (hasEncrypted && !settings.password_set) {
      actualPasswordSet = true;
      settingsManager.saveSettings({ ...settings, password_set: true });
    }

    return {
      success: true,
      password_set: actualPasswordSet,
      has_encrypted: hasEncrypted,
      has_plain: unlocked,
      needs_password: hasEncrypted && !unlocked
    };
  } catch (error) {
    console.error('Failed to check password data:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('lock-passwords', () => {
  try {
    if (sessionPasswords && sessionPasswords.length > 0 && !sessionMasterPassword) {
      // Defensive: should be unreachable now that every mutation requires a
      // master password, but never silently drop passwords.
      return {
        success: false,
        error: 'master_password_required',
        message: 'Master password required to encrypt passwords before locking'
      };
    }
    if (isUnlocked()) {
      saveVault();
    }
    lockSession();
    console.log('Vault locked');
    return { success: true };
  } catch (error) {
    console.error('Failed to lock passwords:', error);
    return { success: false, error: error.message };
  }
});

// --- IPC: S3 sync ---
//
// Direction is decided by the logical timestamp stored INSIDE the backup
// payload (stamped whenever the vault content changes), never by file
// modification times. Only ciphertext ever leaves the machine.

ipcMain.handle('sync-to-s3', async () => {
  try {
    if (!s3Settings.accessKey || !s3Settings.secretKey || !s3Settings.bucketName) {
      throw new Error('S3 configuration incomplete. Please check your settings: Access Key, Secret Key, and Bucket Name are required.');
    }

    const localEncrypted = passwordStore.get('passwords_encrypted') || null;
    let localUpdatedAt = passwordStore.get('vault_updated_at') || null;

    const s3Sync = new S3Sync(s3Settings.region, s3Settings.accessKey, s3Settings.secretKey);
    const remote = await s3Sync.downloadJson(s3Settings.bucketName, S3_BACKUP_KEY);

    if (!localEncrypted) {
      if (remote && remote.encrypted_passwords) {
        adoptRemoteBackup(remote);
        return {
          success: true,
          result: 'downloaded',
          message: 'Encrypted backup downloaded from S3.',
          redirect_to_unlock: true
        };
      }
      return {
        success: true,
        result: 'no_backup_found',
        message: 'No backup found on S3. Starting fresh.',
        redirect_to_main: true
      };
    }

    // Vaults from before this version have no timestamp; stamp them now so
    // comparisons work from here on.
    if (!localUpdatedAt) {
      localUpdatedAt = new Date().toISOString();
      passwordStore.set('vault_updated_at', localUpdatedAt);
    }

    if (remote && remote.encrypted_passwords) {
      if (remote.encrypted_passwords === localEncrypted) {
        return { success: true, result: 'in-sync', message: 'Passwords are already in sync' };
      }
      const remoteTime = Date.parse(remote.vault_updated_at || '') || 0;
      const localTime = Date.parse(localUpdatedAt) || 0;
      if (remoteTime > localTime) {
        adoptRemoteBackup(remote);
        return {
          success: true,
          result: 'downloaded',
          message: 'A newer encrypted backup was downloaded from S3 and replaced the local vault.',
          redirect_to_unlock: true
        };
      }
      // Local is newer (or the remote backup predates version stamping):
      // upload, replacing the remote copy.
    }

    await s3Sync.uploadJson(s3Settings.bucketName, S3_BACKUP_KEY, {
      format: 2,
      vault_updated_at: localUpdatedAt,
      encrypted_passwords: localEncrypted
    });

    return { success: true, result: 'uploaded', message: 'Encrypted backup uploaded' };
  } catch (error) {
    console.error('S3 sync failed:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('restore-from-s3', async () => {
  try {
    if (!s3Settings.accessKey || !s3Settings.secretKey || !s3Settings.bucketName) {
      throw new Error('S3 configuration incomplete. Please check your settings: Access Key, Secret Key, and Bucket Name are required.');
    }

    const s3Sync = new S3Sync(s3Settings.region, s3Settings.accessKey, s3Settings.secretKey);
    const remote = await s3Sync.downloadJson(s3Settings.bucketName, S3_BACKUP_KEY);

    if (!remote || !remote.encrypted_passwords) {
      throw new Error('No valid backup found on S3');
    }

    adoptRemoteBackup(remote);
    console.log('Encrypted backup restored from S3');

    return {
      success: true,
      message: 'Encrypted backup restored successfully. Please unlock with your master password.',
      backup_timestamp: remote.vault_updated_at || 'Unknown'
    };
  } catch (error) {
    console.error('S3 restore failed:', error.message);
    return { success: false, error: error.message };
  }
});

// --- Window / app lifecycle ---

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

  // Always start locked.
  lockSession();
  win.loadFile('unlock.html');

  win.on('closed', () => {
    lockSession();
  });
}

app.whenReady().then(() => {
  cleanupLegacyPlaintext();
  migrateS3SecretToSafeStorage();
  loadS3SettingsIntoMemory();
  createWindow();
});

app.on('before-quit', () => {
  // Every vault mutation is saved eagerly, so this is only a safety net.
  try {
    if (isUnlocked()) {
      saveVault();
    }
  } catch (error) {
    console.error('Failed to save vault on quit:', error);
  }
  lockSession();
});
