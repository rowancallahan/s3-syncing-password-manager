const crypto = require('crypto');

// Vault format v2: scrypt key derivation + AES-256-GCM authenticated encryption.
// Older vaults (crypto-js output: OpenSSL "Salted__" format, EVP_BytesToKey with
// MD5 and AES-256-CBC) are still readable so they can be migrated on unlock.

const VAULT_VERSION = 2;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

// OWASP-recommended minimum scrypt cost (N=2^17, r=8, p=1, ~128 MiB).
const SCRYPT_N = 2 ** 17;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 256 * 1024 * 1024;

// scrypt is deliberately slow, so cache the derived key per (password, salt).
// The salt only changes when the master password is set or changed, which lets
// every save after unlock reuse the key instead of paying the KDF cost again.
const keyCache = new Map();

function deriveKey(password, saltB64, params) {
  const cached = keyCache.get(saltB64);
  if (cached && cached.password === password) {
    return cached.key;
  }
  const key = crypto.scryptSync(password, Buffer.from(saltB64, 'base64'), KEY_LENGTH, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: SCRYPT_MAXMEM
  });
  keyCache.set(saltB64, { password, key });
  return key;
}

// Encrypts plaintext under password. Pass reuseSaltB64 (from a previously
// decrypted v2 vault) to keep the same salt and hit the key cache; omit it to
// generate a fresh salt (initial setup or master password change).
function encryptVault(plaintext, password, reuseSaltB64 = null) {
  if (!password) throw new Error('A password is required for encryption');
  const saltB64 = reuseSaltB64 || crypto.randomBytes(SALT_LENGTH).toString('base64');
  const params = { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P };
  const key = deriveKey(password, saltB64, params);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return JSON.stringify({
    v: VAULT_VERSION,
    kdf: 'scrypt',
    N: params.N,
    r: params.r,
    p: params.p,
    salt: saltB64,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: ciphertext.toString('base64')
  });
}

// Decrypts a stored vault blob. Returns { plaintext, legacy, saltB64 }.
// Throws on a wrong password or tampered data (GCM tag check for v2 vaults).
function decryptVault(stored, password) {
  if (!password) throw new Error('A password is required for decryption');
  let parsed = null;
  try {
    parsed = JSON.parse(stored);
  } catch (e) {
    // Not JSON: fall through to the legacy format.
  }
  if (parsed && parsed.v === VAULT_VERSION && parsed.kdf === 'scrypt') {
    const key = deriveKey(password, parsed.salt, { N: parsed.N, r: parsed.r, p: parsed.p });
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(parsed.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(parsed.tag, 'base64'));
    let plaintext;
    try {
      plaintext = Buffer.concat([
        decipher.update(Buffer.from(parsed.data, 'base64')),
        decipher.final()
      ]).toString('utf8');
    } catch (e) {
      // keyCache may hold a key derived from a wrong password; drop it so a
      // corrected password re-derives.
      keyCache.delete(parsed.salt);
      throw new Error('Invalid master password or corrupted vault data');
    }
    return { plaintext, legacy: false, saltB64: parsed.salt };
  }
  return { plaintext: decryptLegacy(stored, password), legacy: true, saltB64: null };
}

// crypto-js compatible decryption: base64("Salted__" + 8-byte salt + AES-256-CBC
// ciphertext), key and IV derived via OpenSSL EVP_BytesToKey (single-pass MD5).
// Unauthenticated and weak by design of the old format — used for migration only.
function decryptLegacy(stored, password) {
  const raw = Buffer.from(String(stored), 'base64');
  if (raw.length < 32 || !raw.subarray(0, 8).equals(Buffer.from('Salted__'))) {
    throw new Error('Unrecognized vault format');
  }
  const salt = raw.subarray(8, 16);
  const body = raw.subarray(16);
  let keyIv = Buffer.alloc(0);
  let block = Buffer.alloc(0);
  while (keyIv.length < KEY_LENGTH + 16) {
    block = crypto.createHash('md5')
      .update(Buffer.concat([block, Buffer.from(password, 'utf8'), salt]))
      .digest();
    keyIv = Buffer.concat([keyIv, block]);
  }
  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      keyIv.subarray(0, KEY_LENGTH),
      keyIv.subarray(KEY_LENGTH, KEY_LENGTH + 16)
    );
    const plaintext = Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
    if (!plaintext) throw new Error('empty');
    return plaintext;
  } catch (e) {
    throw new Error('Invalid master password or corrupted vault data');
  }
}

module.exports = { encryptVault, decryptVault };
