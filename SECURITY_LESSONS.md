# Security Lessons — what went wrong, why, and what to read

This is the companion to `DESIGN_REVIEW.md`. That file lists *what* was wrong;
this one explains the underlying principle behind each mistake, how the fix on
this branch applies it, and where to read more so you can catch these yourself
next time. The unifying theme: none of the bugs were exotic. Each one came from
trusting a plausible-looking abstraction (a storage library, a crypto API, a
file timestamp, a config file) without asking one probing question about what it
actually does.

---

## Lesson 1 — Know where your bytes physically land

**The bug:** the code kept "session" passwords in `electron-store` with comments
saying *"Keep in memory ONLY for current session."* But `electron-store` is a
disk-persistence library — every `.set()` synchronously writes a plaintext JSON
file. The comments described the intent; the library did something else. Result:
the decrypted vault sat on disk the whole time the app was unlocked, and
survived any crash.

**The principle:** for every piece of sensitive data, be able to answer: *what
file does this end up in, when is it deleted, and what happens if the process
dies before that?* "At rest" vs "in memory" is a physical distinction, not a
naming convention. A variable is memory; anything that goes through a store,
cache, log, or ORM is disk until proven otherwise.

**The fix (this branch):** decrypted entries live in a plain module variable
(`sessionPasswords` in `main.js`); the store holds only ciphertext. About 300
lines of "clean plaintext up on startup/lock/close" code became unnecessary and
was deleted — compensating code disappearing is usually the sign you fixed the
real problem.

**How to test it yourself:** unlock the app, `kill -9` the process, then open
`~/.config/syncpass/syncpass_password_store.json` (or the macOS equivalent under
`~/Library/Application Support`). Before the fix you'd see your passwords. This
"crash then read the disk" test is worth running on anything that claims to keep
secrets in memory. Also grep for a red flag pattern: comments asserting security
properties ("SECURITY: never saved to disk"). Comments can't enforce anything —
each one is a claim to verify, not a fact.

---

## Lesson 2 — Password encryption is a *system* (KDF + AEAD), not a function call

**The bug:** `CryptoJS.AES.encrypt(data, "master password")` looks like
industrial-strength crypto. It isn't, for three separate reasons:

1. **No real key derivation.** Passing a *string* password to crypto-js invokes
   OpenSSL's legacy `EVP_BytesToKey` — a single MD5 pass — to turn the password
   into a key. Password→key derivation must be *expensive* (memory-hard,
   tunable), because your attacker's cost per guess is exactly the cost of the
   KDF. One MD5 means billions of guesses per second on a GPU; a stolen vault
   file or S3 bucket falls to offline brute force. (Even `openssl` prints
   "WARNING: deprecated key derivation used" for this construction now.)
2. **No authentication.** AES-CBC without a MAC means ciphertext can be
   tampered with undetected, and "wrong password" is only discovered when the
   output fails to parse. Encryption without integrity is half a scheme.
3. **Insecure randomness in the generator.** `Math.random()` is a predictable
   PRNG; using it to generate the passwords a password manager exists to
   protect defeats the purpose.

**The principle:** never assemble crypto from primitive names. Use the boring,
current, complete answer: a memory-hard KDF (Argon2id or scrypt) to get from
password to key, and an AEAD cipher (AES-256-GCM or ChaCha20-Poly1305) to
encrypt. If your code mentions MD5, SHA-1, ECB, CBC-without-MAC, or derives a
key from a password without a cost parameter, stop. And version your format so
you can migrate later — crypto choices always change.

**The fix (this branch):** `vault_crypto.js` uses Node's built-in `crypto`:
scrypt (N=2¹⁷, r=8, p=1 — OWASP's recommended minimum, ~0.8s per derivation)
with a random salt, then AES-256-GCM with a fresh IV per write. The blob is a
versioned JSON envelope (`{v: 2, kdf, N, r, p, salt, iv, tag, data}`), old
crypto-js vaults are decrypted once for migration and immediately re-encrypted
in the new format, the derived key is cached per (password, salt) so routine
saves don't pay the KDF cost, the generator uses `crypto.getRandomValues` with
rejection sampling, and the master-password minimum is 12 characters —
because against offline attack, the KDF and the password are all there is.

**How to test it yourself:** the properties are testable without being a
cryptographer — see the round-trip / wrong-password / flipped-byte tests used
for this branch. If you can flip a byte in the stored blob and decryption still
"succeeds", you don't have authenticated encryption.

---

## Lesson 3 — Sync is a distributed-systems problem, not a file copy

**The bug:** `syncFile()` compared the local backup's filesystem mtime with the
S3 object's `LastModified` to pick a winner. But the sync handler *rewrote the
local backup file just before comparing*, so local mtime was always "now" and
the download branch was unreachable — every sync uploaded, silently clobbering
edits from your other machine. The mechanism designed to prevent data loss
guaranteed it.

**The principle:** two machines editing one datum is replication, and you need
to decide — explicitly — how conflicts resolve. File mtimes are the wrong input:
they record when *a file was written*, not when *the data changed*, and they
depend on each machine's clock. The minimum viable design is a logical
modification stamp stored *inside* the payload, set only when content actually
changes, plus an explicit rule ("newest content wins") and a recovery story for
when that rule picks wrong (S3 bucket versioning — turn it on for this bucket).
Whole-vault last-writer-wins still loses one side of a true simultaneous-edit
conflict; per-entry timestamps and merge would be the next step, and CRDTs are
the deep end of this pool.

**The fix (this branch):** every vault save stamps `vault_updated_at` in the
store; the S3 payload carries it (`{format: 2, vault_updated_at,
encrypted_passwords}`); sync compares those stamps, downloads when remote is
strictly newer (then forces re-unlock), uploads otherwise, and short-circuits
when ciphertexts are identical. The temp-file dance is gone entirely.

**How to test it yourself:** simulate two machines with two user-data dirs.
Edit on A, sync; edit on B, sync; sync A again. Before the fix, B's edit is
gone. Any sync feature deserves this three-step test before you trust it.

---

## Lesson 4 — Secrets don't belong in dotfiles (or in the DOM)

**The bug:** the AWS secret key sat in plaintext in `~/.syncpass-settings.yml`
and was echoed back into the settings form, readable by any process (or any
rogue script in the renderer) that can read your home directory or the page.

**The principle:** anything that can read files as your user gets everything in
your dotfiles — that's the local threat model. Operating systems ship a keychain
(Keychain/DPAPI/libsecret) precisely so apps don't roll their own secret
storage; Electron exposes it as `safeStorage`. And secrets should flow one way:
UI → main process → keychain. Sending a stored secret *back* to the UI, even
just to prefill a form, widens exposure for zero benefit — every real cloud
console shows "saved" instead of the key.

**The fix (this branch):** the secret is encrypted with `safeStorage` (existing
plaintext settings are migrated on first launch, with plaintext-plus-warning as
fallback only where no OS keychain exists), `get-settings` returns only a
`s3SecretKeySet` boolean, and an empty field on save means "keep the stored
secret".

---

## Lesson 5 — How to work with AI-generated code on security-sensitive projects

This codebase's README already had the right instinct ("further testing
required to make sure claude code didn't add any surprises"). The refinement:
the risk usually isn't *added surprises*, it's **confidently asserted
properties that were never true** — code that logs `SECURITY: Passwords
encrypted and saved securely` while writing plaintext two lines later. What
works:

- **Verify claims, not vibes.** Every security-relevant comment or log line is
  a hypothesis. Test the three big ones directly: what's on disk when the
  process dies (Lesson 1), what happens with a wrong password or corrupted
  blob (Lesson 2), what happens with two writers (Lesson 3).
- **Ask "what library call actually executes?"** The plaintext-on-disk bug and
  the MD5-KDF bug were both one documentation lookup away
  (`electron-store` → "persists to a JSON file"; crypto-js `encrypt(msg,
  string)` → "OpenSSL-compatible KDF").
- **Prefer designs that delete failure modes over code that manages them.**
  The old code managed plaintext-on-disk with cleanup at six call sites; the
  fix made the state unrepresentable. When you see the same defensive dance
  repeated everywhere, look for the design change that makes it unnecessary.
- **Keep a written threat model, even three lines.** "Attacker has my vault
  file / my S3 bucket / a process on my machine" immediately flags the weak
  KDF, the plaintext store, and the dotfile secret.

---

## Reading list

Ordered by usefulness for *this* project.

**Books**

1. **Real-World Cryptography — David Wong (Manning, 2021).** The single best
   match: KDFs, authenticated encryption, secure randomness, and end-to-end
   encrypted application design, written for developers, not mathematicians.
   Chapters 3 (MACs), 4 (AEAD), and 8 (randomness) map one-to-one onto Lesson 2.
2. **Serious Cryptography, 2nd ed. — Jean-Philippe Aumasson (No Starch, 2024).**
   Deeper "why" behind the same material — what actually breaks when you use
   unauthenticated CBC or a fast hash as a KDF.
3. **Designing Data-Intensive Applications — Martin Kleppmann (O'Reilly).**
   Chapter 5 (replication, last-writer-wins and its data loss) and chapter 8
   (unreliable clocks) are Lesson 3 in book form.
4. **Security Engineering, 3rd ed. — Ross Anderson.** Threat-modeling breadth;
   the full text is free on the author's site (cl.cam.ac.uk/~rja14/book.html).
   Skim chapters rather than reading cover to cover.
5. **Cryptography Engineering — Ferguson, Schneier & Kohno.** Older, but the
   best source for the *mindset*: every crypto design choice is guilty until
   proven innocent.

**Papers, posts, and docs**

- **Latacora — "Cryptographic Right Answers"** (latacora.com, 2018): the
  canonical one-page cheat sheet ("password handling: scrypt or argon2";
  "encrypting: AES-GCM"). If the app had followed this one post, Lesson 2
  wouldn't exist.
- **OWASP Password Storage Cheat Sheet** (cheatsheetseries.owasp.org): current
  Argon2id/scrypt parameter recommendations — where this branch's scrypt
  numbers come from.
- **Filippo Valsorda — "The scrypt parameters"** (words.filippo.io): short,
  practical walkthrough of what N/r/p actually trade off.
- **Moxie Marlinspike — "The Cryptographic Doom Principle"** (moxie.org, 2011):
  why authenticate-then-decrypt ordering matters; the classic argument for AEAD.
- **1Password Security Design white paper** (support.1password.com) and the
  **Bitwarden Security Whitepaper** (bitwarden.com/help): how real password
  managers structure exactly this problem — KDF choices, what the server/bucket
  is allowed to see, sync. Reading either is the fastest way to calibrate "what
  does done look like" for this app.
- **Electron security guidelines**
  (electronjs.org/docs/latest/tutorial/security): the checklist this app
  already half-followed (context isolation ✓) — worth finishing, and it covers
  `safeStorage`.
- **Ink & Switch — "Local-first software"** (inkandswitch.com/local-first):
  the long-view essay on sync, conflicts, and CRDTs, if the sync problem ever
  graduates from "newest vault wins" to real merging.

**Still open on this branch** (see `DESIGN_REVIEW.md` for the full list): the
quote-unsafe `escapeHtml` used in HTML attributes (switch row rendering to DOM
APIs), the unimplemented `clipboardAutoClear` setting, hardcoded Desktop export
path, and the absence of automated tests beyond the crypto module's.
