# Changelog

All notable changes to Local Vault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
