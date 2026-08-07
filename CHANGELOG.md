# Changelog

All notable changes to Local Vault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] - 2026-08-07

### Added
- passwords.js - mergeVaults() reconciles two vaults credential by credential
  - Match key is the decrypted username within a domain
  - Same username, newest updatedAt wins, the older password is discarded
  - Different usernames on the same domain coexist as separate logins
  - Domains present on only one device are preserved
- passwords.js - reEncryptVault() swaps a vault from one master key to another without altering contents
- pairing.js - receiveTransfer() now merges instead of overwriting
  - The vault with the oldest meta.createdAt supplies the shared master key
  - The other device re-encrypts its credentials under that shared key before merging
  - Merged vault keeps the oldest createdAt so the key rule stays stable across future syncs
- passwords.js - deleteCredential() writes a tombstone instead of removing the entry
  - Tombstone carries deleted, deletedAt, and updatedAt, and clears the encrypted secrets
  - A newer tombstone beats an older credential on merge and removes it from both devices
- extension/pairing.js - pairing logic ported into the extension so it can participate in sync

### Changed
- getCredentials() and getAllDomains() skip tombstones, so deleted entries stay invisible to the UI and autofill while remaining available to the merge
- saveCredential() replaces an existing credential for the same username rather than duplicating it
- Unlock methods (fingerprint, PIN, password) stay local to each device and never enter a transfer. Only stored website credentials sync.

### Notes
- Master key selection and credential contents are governed by two independent rules. Oldest createdAt decides the shared encryption key. Newest updatedAt decides which password is current. They never interact.
- The master key is not user facing. When a late sync introduces an older device, the shared key silently converges to that older key with no visible effect on stored logins.
- Devices converge. If every device eventually syncs with the group, all devices land on the same master key and the same credential set.
- Merge logic is identical across the app and the extension. Both projects share the same passwords.js and pairing.js.
- All merge behavior validated in Node against WebCrypto: oldest-key-wins, re-encryption under the shared key, newest password replacing the old, coexisting usernames, tombstone deletion, one-sided domain preservation, createdAt convergence.

### In Progress
- QR pairing UI on both the app and the extension so a user can start a sync
- Comparison code confirmation screen during pairing

## [0.3.1] - 2026-08-05

### Added
- extension/ — browser extension brought into the repo (settings page, autofill dropdown, toolbar popup, content script)
- extension/background.js — service worker answering credential requests so the autofill dropdown populates whether or not the popup is open
- Autofill dropdown renders on login fields and fills saved credentials for the current domain
- Session key bridged to the worker via chrome.storage.session — memory only, cleared on browser close

### Fixed
- Autofill dropdown showed an empty box when the popup was closed — the worker now serves credentials independently
- Extension carried the pre-0.3.0 crypto — now on the same secure core as the app (WebAuthn PRF, verify-by-unwrap, PBKDF2 600k)

### Changed
- Extension PIN, password, and fingerprint unlock rebuilt on the secure crypto core with no stored verification hashes
- Extension version aligned to 0.3.1

### In Progress
- Settings and options page access from the popup — actively being built
- Full autofill profile (name, address, email, phone) alongside credentials — actively being built
- Save credentials during signup rather than manual entry — actively being built

### Notes
- Autofill detection currently wires on fields present at page load — dynamic-form coverage is part of the in-progress autofill work
- App and extension now share one crypto and auth core

## [0.3.0] - 2026-08-04

### Fixed
- auth.js - fingerprint wrapping key no longer derived from a hardcoded constant
  - Previous behavior: wrapping key derived from a public string plus a salt stored beside the ciphertext - the WebAuthn prompt was a UI gate only, its result never used
  - Any party with database access could unwrap the master key without touching the biometric
  - Fingerprint-wrapped keys are now bound to authenticator secret material via WebAuthn PRF
- crypto.js - stored PIN and password verification hashes removed entirely
  - Previous behavior: 4-round SHA-256 verification hashes stored beside the wrapped keys gave offline attackers a fast oracle, bypassing the full KDF cost
  - Wrong credentials now fail at the AES-GCM unwrap - every offline guess pays the full derivation cost
- pairing.js - generatePairingCode() modulo bias removed via rejection sampling
- store.js - clearAll() now awaits transaction completion - wipes commit before returning
- build.js - status indicator element IDs corrected to match markup - indicators were silently dead
- build.js - session status indicator wired to live session state

### Added
- crypto.js - deriveKeyFromPrfOutput() - HKDF-SHA256 derivation from WebAuthn PRF output to AES-GCM wrapping key
- crypto.js - PBKDF2_ITERATIONS raised to 600,000 - LEGACY_PBKDF2_ITERATIONS retained at 100,000 for migration unwraps
- auth.js - WebAuthn PRF enrollment flow
  - PRF extension requested at credential creation with a random 32-byte eval salt
  - PRF output taken at creation when the platform returns it there, otherwise via one assertion
  - Devices without PRF support are refused honestly - no fake biometric gate is ever presented
  - fingerprintCredentialId and fingerprintPrfSalt stored per enrollment
- auth.js - upgradeWrap() - silent rewrap migration on successful unlock
  - Legacy 100k-iteration wraps rewrapped at 600k with a fresh salt
  - Lingering legacy hash fields deleted during migration
- auth.js - authenticateLegacyFingerprint() - one-time migration unwrap for pre-0.3.0 fingerprint enrollments, deletes the insecure wrap, returns requiresReenroll
- auth.js - authenticateLegacyPIN() - one-time migration unlock for pre-0.3.0 PIN-wrapped vaults, purges persistent PIN fields, returns requiresAuthSetup when no other method exists
- auth.js - per-method kdfIterations field persisted with each wrap - future cost raises migrate the same way
- session.js - ephemeral session PIN system
  - setSessionPin() - encrypts the exported master key under a PIN-derived key with a fresh in-memory salt
  - softLockNow() - inactivity lock nulls the raw key, retains only the PIN-encrypted blob
  - resumeWithPin() - decrypts and restores the master key on correct PIN
  - Three failed resume attempts trigger a full hard wipe - vault requires password or fingerprint
  - isSoftLocked(), hasSessionPin(), clearSessionPin() state helpers

### Changed
- Credential verification is now unwrap-based - the AES-GCM auth tag is the verifier, nothing cheaper than the wrap exists in storage
- PIN demoted from persistent wrap method to ephemeral session resume
  - PIN never touches disk - it exists only in memory for the current session
  - Force-closing the app clears it by design - a fresh session requires the real credential
  - Cold-start unlock is password or fingerprint only
- Fresh salt generated on every credential set - salts are never reused across changes
- removeFingerprint() requires a password backup - PIN no longer counts as a recovery path
- removePassword() requires a fingerprint backup
- Session inactivity timeout soft-locks when a session PIN is set, hard-locks otherwise
- Rebranded Valid Vault to Local Vault - page title, header, WebAuthn RP name, boot log
- Header carries a two-line identity - Local Vault over Password Manager

### Removed
- FINGERPRINT_SECRET hardcoded constant - retained internally only for the legacy migration unwrap
- sha256Kdf(), hashPin(), hashPassword(), arraysEqual() from crypto.js
- setPIN(), authenticatePIN(), removePIN(), startPINCreation() from auth.js
- pinWrappedKey, pinSalt, pinHash, pinKdfIterations from persistent auth storage - purged on any successful unlock

### Security
- **CRITICAL:** Fingerprint path previously provided zero cryptographic protection - vault contents were recoverable from the database alone when fingerprint was enrolled
- **CRITICAL:** Stored verification hashes reduced offline attack cost from 100k PBKDF2 iterations per guess to 4 SHA-256 rounds per guess
- 4-6 digit PINs cannot survive offline attack at any iteration count - resolved structurally by removing PIN from persistent storage rather than by raising cost
- At rest, the database now contains only 600k-iteration password wraps and PRF-bound fingerprint wraps

### Notes
- Session PINs are ephemeral by design - nothing is stored, nothing can be extracted, nothing can be brute-forced offline
- PRF requires a WebAuthn authenticator with PRF extension support - Chrome on Android with a screen-lock credential qualifies, Capacitor WebView behavior requires on-device validation
- Master key round-trips through extractable raw bytes during enrollment of additional methods - unavoidable in pure WebCrypto without hardware keystore binding
- Domain names in vault storage remain plaintext object keys - vault blob encryption is the next scheduled schema change
- All crypto flows validated in Node against WebCrypto - wrap/unwrap round trips, wrong-secret rejection, legacy-to-current migration, PRF-derived wrapping, session PIN lifecycle including 3-attempt wipe

## [0.2.0-alpha] - 2025-11-28

### Added
- Master key wrap architecture - one random 256-bit master key wrapped independently per unlock method
- Fingerprint, PIN, and password unlock paths
- Per-credential AES-GCM encryption of stored usernames and passwords
- ECDH device pairing over QR with numeric comparison code
- Encrypted vault transfer between paired devices with HMAC payload signature
- Session management with inactivity timeout
- IndexedDB persistence - auth, passwords, wallets stores
- Capacitor Android wrapper
- Single-file bundler (build.js) - modules assembled into test.html

### Notes
- Alpha status - key protection layer contains known weaknesses corrected in 0.3.0
- Earlier iterations were not formally tagged

---

[0.3.0]: https://github.com/HiImRook/local-vault-password-manager/releases/tag/v0.3
[0.2.0-alpha]: https://github.com/HiImRook/local-vault-password-manager/releases/tag/v0.2.0-alpha
