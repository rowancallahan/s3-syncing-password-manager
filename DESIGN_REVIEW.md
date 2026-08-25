# Design Review — SyncPass (S3-Syncing Password Manager)

Reviewed: 2026-08-25. Scope: `main.js`, `preload.js`, `s3_sync.js`, `index.html`, `unlock.html`, `package.json`.

## Verdict

The high-level architecture is sound: an Electron app with a locked-down renderer, a
master-password-encrypted vault, and only-ciphertext-leaves-the-machine S3 sync is a
reasonable design for a self-hosted password manager. Several implementation-level
design decisions, however, undermine the security goals the app states in its own
comments, and one undermines the syncing itself. The four issues in "Critical" below
are the ones worth fixing before daily use.

## What's designed well

- **Electron process isolation is correct.** `contextIsolation: true`,
  `nodeIntegration: false`, and a `preload.js` that exposes a narrow, explicit API via
  `contextBridge` is exactly the recommended setup. The renderer never touches `fs`,
  AWS credentials, or the crypto library directly.
- **Only ciphertext is synced.** The S3 backup contains only the encrypted blob, and
  restore forces a re-unlock. S3 credentials live in the main process, not the window.
- **Lock-by-default startup.** Always booting into `unlock.html`, clearing the session
  master password on startup, and reconciling a stale `password_set` flag against the
  actual presence of encrypted data are good defensive choices.
- **Small dependency footprint** (three runtime deps) keeps the audit surface small.

## Critical issues

### 1. "In-memory" decrypted passwords are actually written to disk

Throughout `main.js`, the decrypted vault is kept in
`passwordStore.set('passwords', ...)` with comments like "Keep in memory ONLY for
current session." `electron-store` is not memory — every `.set()` synchronously
persists to a plaintext JSON file in `userData`. So for the entire time the vault is
unlocked, **all passwords sit on disk in cleartext**, and if the app crashes or the
machine loses power, they stay there. The startup cleanup
(`clearPlainPasswordsOnStartup`) only mitigates this after a clean next launch.

**Fix:** hold the decrypted array in a plain module-level variable
(`let sessionPasswords = null`) alongside `sessionMasterPassword`, and reserve
`passwordStore` for the `passwords_encrypted` blob only. This is a small refactor —
every `passwordStore.get('passwords')` / `.set('passwords', ...)` /
`.delete('passwords')` becomes a variable read/write — and it eliminates the whole
class of "clear plaintext on startup/close/lock" code, which exists only to
compensate for this decision.

### 2. The cryptography is far below password-manager grade

`CryptoJS.AES.encrypt(json, passphrase)` with a string passphrase uses OpenSSL's
legacy `EVP_BytesToKey` key derivation: **one round of MD5**, no memory-hard KDF.
A stolen vault file can be brute-forced at GPU speeds; combined with the 6-character
minimum master password, offline cracking is practical. There is also **no
authentication (MAC)** — ciphertext is malleable and "wrong password" is detected
only by UTF-8/JSON decode failure. On top of that, `crypto-js` is discontinued
(its own README says to migrate to native crypto), and the password generator uses
`Math.random()`, which is not cryptographically secure.

**Fix:** use Node's built-in `crypto` in the main process:
- Derive the key with `scrypt` (or Argon2id via a maintained lib) and a random salt.
- Encrypt with AES-256-GCM; store `salt || iv || tag || ciphertext`.
- Version the vault format (`{v: 2, salt, iv, tag, data}`) so old vaults can be migrated on unlock.
- Generate passwords with `crypto.randomInt` / `webcrypto.getRandomValues`.
- Raise the master-password minimum (12+) since it's the only thing protecting the S3 copy.

### 3. Sync is last-writer-wins by mtime — and local always wins

`syncFile()` compares the local file's `mtime` against S3 `LastModified`. But
`sync-to-s3` **rewrites `~/.syncpass_encrypted_backup.json` immediately before every
sync**, so the local mtime is always "now" and the `s3Modified > localModified`
download branch is effectively unreachable. In practice every sync uploads,
silently clobbering changes made on another machine — the exact scenario a syncing
password manager exists to handle. Even without that bug, whole-file
mtime-comparison sync is clock-skew sensitive and merges nothing.

**Fix:** at minimum, store a logical timestamp/counter inside the backup payload
(set when the vault content actually changes, not when the file is written) and
compare that, warn before overwriting a newer remote, and recommend enabling S3
bucket versioning so a bad sync is recoverable. A nicer end state is per-entry
`updatedAt` fields with entry-level merge.

### 4. AWS credentials stored and displayed in plaintext

The S3 secret key is written unencrypted to `~/.syncpass-settings.yml` and echoed
back into the settings form. Anything that can read the user's home directory gets
credentials that can read (and delete/overwrite) the vault backup.

**Fix:** store the S3 secret with Electron's `safeStorage` (OS keychain-backed), or
encrypt it under the master key. Also scope the IAM user to
`GetObject`/`PutObject`/`HeadObject` on the single bucket, and document that.

## Significant issues

- **`escapeHtml()` doesn't escape quotes, and values are interpolated into HTML
  attributes.** `div.textContent → div.innerHTML` escapes `& < >` but not `"`. Rows
  are built as `value="${this.escapeHtml(password.website)}"`, so an imported file
  (or a synced vault from another machine) containing `" onfocus="..."` in a field
  breaks out of the attribute — stored XSS in a renderer that holds the whole
  decrypted vault and the `electronAPI` bridge. Build rows with DOM APIs
  (`createElement` + `.value = ...`) instead of `innerHTML` templates; that also
  removes the need for the global `onclick="passwordUI...."` handlers.
- **A mistyped password can silently become the master password.** In
  `unlock-with-master-password`, if plain passwords exist without an encrypted blob,
  whatever is typed at the unlock prompt is used to encrypt them. There's no
  confirmation field on that path, so a typo permanently locks the vault under an
  unknown password. Route this state through the explicit "set master password"
  (enter-twice) flow instead.
- **Plaintext secrets are logged.** `console.log('Initial store contents:', passwordStore.store)`
  and the "Final store contents before quit" log print the decrypted vault to
  stdout when unlocked. Together with the very chatty `=== SECURITY ... ===` logging,
  this belongs behind a debug flag with secrets redacted.
- **Two parallel unlock implementations and seven copies of encrypt-and-save.**
  `unlock.html` and the `masterPasswordModal` in `index.html` duplicate the unlock
  flow, and the encrypt→`passwordStore.set`→update-settings sequence is repeated in
  `set-passwords`, `add-password`, `update-password`, `delete-password`, `lock-passwords`,
  `set-master-password`, `reset-master-password`, and `before-quit`. Extract a single
  `saveVault(passwords)` / `unlockVault(password)` module in the main process; most
  of the state-reconciliation branches disappear once plaintext is never persisted
  (issue #1).
- **`clipboardAutoClear` is a setting that does nothing.** `copyPassword` never
  clears the clipboard. Either implement it (clear after ~30s if the clipboard still
  holds the copied value) or remove the toggle — a security setting that silently
  no-ops is worse than its absence.

## Minor issues

- **`before-quit` races a fixed 500 ms timer** (`event.preventDefault()` then
  `app.exit()` in a `setTimeout`). The save work is synchronous, so either do it and
  exit deterministically, or drop the timer; as written, a slow disk could get the
  process killed mid-write.
- **Export always writes to `~/Desktop`**, which doesn't exist on many Linux setups
  and is relocated by OneDrive on Windows. Use `dialog.showSaveDialog`.
- **Auto-lock rearms on every mousemove** via ~20 document-level listeners calling
  `manageAutoReturnTimer` (clearing and recreating timers, throttled to 100 ms). One
  `resetTimer()` on a small set of events (`mousedown`, `keydown`, `wheel`,
  `touchstart`) is enough. Also, when the timer expires but no master password is
  set, the app shows a modal and stays unlocked indefinitely — for a "sleep screen"
  feature, defaulting to hiding the list would be safer.
- **Hand-rolled YAML parsing/serialization** in two places (`SettingsManager`,
  import). It strips all `"` characters from values and truncates at the second `:`.
  Settings could just be JSON, or use a real YAML lib.
- **`npm run build` targets only `darwin/arm64`** while the README implies general
  use; and `npm test` is a stub — the README's own "further testing required" note
  is right, and the crypto round-trip (encrypt→decrypt, wrong-password, tamper) is
  the first thing worth a test.

## Suggested order of work

1. Stop persisting plaintext (issue #1) — small change, biggest payoff.
2. Replace crypto-js with native scrypt + AES-256-GCM and a versioned vault format (#2).
3. Fix sync to compare vault content versions, not file mtimes (#3).
4. Move S3 credentials to `safeStorage` (#4).
5. DOM-based row rendering to close the attribute-injection hole.
6. Consolidate the vault logic into one module; then the remaining items.
