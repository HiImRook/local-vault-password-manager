# Local Vault Password Manager

A local, encrypted, QR code portable password manager. No cloud, no accounts, or sync servers. Your credentials live on your device, encrypted under keys only you can produce, and move between devices over a QR pairing ceremony.

---

> ✅ **Credential Sync Notice - v0.3.2**
>
> Paired devices now merge their stored credentials instead of overwriting each other. Within a site the username identifies the login, matching usernames resolve to the newest password, and different usernames stay as separate logins. Deletions propagate to both devices. The vault with the oldest creation time supplies the shared master key, which is internal and never shown. Unlock methods stay local to each device and never sync. See [CHANGELOG.md](CHANGELOG.md) for full details.

> ✅ **Security Overhaul Notice - v0.3.0**
>
> The key protection layer has been reworked. Fingerprint unlock is now cryptographically bound to the device authenticator via WebAuthn PRF. Stored verification hashes are gone - wrong credentials fail at the AES-GCM unwrap, so every offline guess pays the full key derivation cost. PBKDF2 raised to 600k iterations with silent migration on unlock. PIN no longer wraps the master key and never touches disk - it is an ephemeral session convenience that clears when the app closes. See [CHANGELOG.md](CHANGELOG.md) for full details.

---

## What is Local Vault?

Local Vault is a self-hosted password manager built on a master key wrap architecture. One random 256-bit master key encrypts your vault. That key is never stored raw, it's wrapped independently under each unlock method you enroll, and unwrapping it is the act of authentication itself.

**How unlock works:**
- Password - wrapping key derived via PBKDF2-SHA256 at 600,000 iterations with a per-wrap salt
- Fingerprint - wrapping key derived via HKDF from WebAuthn PRF output, secret material only your device authenticator can produce
- Session PIN - ephemeral quick unlock for the current session only, held in memory, gone on app close
- Wrong credential means the AES-GCM unwrap fails. There is no stored hash to attack, no shortcut, no oracle.

No cloud service holds your data. No company can be subpoenaed for it, breached for it, and there is never any data for anyone to sell. You cannot leak what you never sent anywhere.

---

## Core Features

**Key Protection:**
- Master key wrap architecture - one key, independently wrapped per unlock method
- Verify-by-unwrap - the GCM auth tag is the verifier, nothing cheaper exists in storage
- WebAuthn PRF fingerprint binding - no PRF support means no fake biometric gate, refused honestly
- Fresh salt on every credential change
- Silent KDF migration - legacy wraps upgrade to current cost on first successful unlock

**Session PIN:**
- Ephemeral by design - never written to disk, exists only for the current session
- Soft lock on inactivity - raw key nulled, only a PIN-encrypted blob remains in memory
- Three wrong attempts wipes the session entirely - back to the real credential
- Force-closing the app clears it. A fresh session means proving you hold the real key.

**Vault:**
- Per-credential AES-GCM encryption of usernames and passwords
- IndexedDB persistence - no external database or server
- Session timeout with automatic lock

**Credential Sync:**
- Devices merge credentials on sync, they do not overwrite each other
- Username is the identity within a site, newest password wins, different usernames coexist
- Deletions propagate to both devices through tombstones
- Oldest creation time supplies the shared master key, other devices re-encrypt under it
- Unlock methods stay local to each device and never sync

**Device Transfer:**
- ECDH pairing over QR code - ephemeral keys per session
- Numeric comparison code - short authentication string against MITM
- AES-GCM encrypted vault transfer with HMAC payload signature
- No relay servers - devices talk directly

**Platform:**
- Single-file web bundle - modules assembled by build.js into one self-contained HTML file
- Android via Capacitor
- Zero runtime dependencies beyond WebCrypto and IndexedDB

## Current Status: v0.3.2

**Completed:**
* ✅ Master key wrap architecture - one random 256-bit key, wrapped per method
* ✅ Verify-by-unwrap - stored verification hashes removed entirely
* ✅ WebAuthn PRF fingerprint binding - wrapping key from authenticator secret material
* ✅ PRF-less devices refused honestly - no decorative biometric gate
* ✅ PBKDF2-SHA256 at 600k iterations - per-method iteration count persisted
* ✅ Silent rewrap migration - legacy 100k wraps upgrade on first unlock with fresh salt
* ✅ PIN demoted to ephemeral session resume - never touches disk
* ✅ Session soft lock - raw key nulled on inactivity, PIN-encrypted blob only
* ✅ Three-attempt session wipe - brute-forcing the resume path ejects to real credentials
* ✅ Legacy PIN vault migration - one-time unlock, purge, prompt for real credential
* ✅ Legacy fingerprint migration - one-time unwrap, insecure wrap deleted, re-enrollment required
* ✅ Fresh salts on every credential set
* ✅ Removal guards - each wrap method requires another as backup before removal
* ✅ ECDH QR pairing with numeric comparison code
* ✅ Encrypted device-to-device vault transfer
* ✅ Pairing code generation free of modulo bias
* ✅ clearAll commits transactions before returning
* ✅ Crypto flows validated in Node against WebCrypto
* ✅ Credential merge engine - username-keyed, newest password wins, different usernames coexist
* ✅ Oldest-key-wins shared master key with re-encryption on adopt
* ✅ Tombstone deletes that propagate across devices
* ✅ Browser extension shares the same merge engine as the app

**In Development:**
* 📋 QR pairing UI on both the app and extension so a user can start a sync
* 📋 Comparison code confirmation screen during pairing
* 📋 Vault blob encryption - domain names currently plaintext object keys
* 📋 On-device PRF validation across Capacitor WebView versions

## Development Phases

### Phase 1: Vault Foundation ✅ (Complete - v0.2.0-alpha)
- Master key wrap architecture
- Fingerprint, PIN, and password unlock paths
- Per-credential encryption
- QR pairing and encrypted transfer
- Capacitor Android wrapper

### Phase 2: Key Protection Overhaul ✅ (Complete - v0.3.0)
- WebAuthn PRF fingerprint binding
- Verify-by-unwrap replaces stored hashes
- PBKDF2 600k with silent migration
- Ephemeral session-only PIN
- Rebrand to Local Vault

### Phase 3: Credential Sync Engine ✅ (Complete - v0.3.2)
- Username-keyed merge, newest password wins
- Oldest creation time supplies the shared master key
- Re-encryption under the shared key on adopt
- Tombstone deletes propagate across devices
- App and extension share one merge engine

### Phase 4: Sync UI 📋 (Future)
- QR pairing flow on both app and extension
- Comparison code confirmation screen
- Sync status and conflict reporting

### Phase 5: Vault Schema Hardening 📋 (Future)
- Single-blob vault encryption - site list becomes invisible at rest
- Vault format version bump with migration
- Fresh IV discipline audit across all encrypt paths

### Phase 6: Platform Hardening 📋 (Future)
- Android hardware keystore binding via Capacitor plugin
- PRF fallback strategy per device capability
- Web build parity decisions

## Sync Model

**Two independent rules govern sync, and they never interact.**

Master key selection uses the oldest creation time. Every device starts with its own master key. When two devices pair, the vault with the oldest creation time supplies the shared master key, and the other device re-encrypts its credentials under it. The master key is internal and never shown, so this convergence is invisible during normal use.

Credential merge uses the newest update time. Within a site the username is the identity. Matching usernames resolve to the newest password and the older one is discarded. Different usernames on the same site remain as separate logins. A credential on only one device is kept.

Deletion uses tombstones. Deleting a credential writes a tombstone carrying a timestamp. On the next sync the tombstone propagates and the credential is removed from both devices. A credential re-added after a deletion carries a newer timestamp, so it survives.

Convergence is guaranteed. If every device eventually syncs with the group, all devices arrive at the same master key and the same set of credentials. Sync order does not matter.

## Security Model

**Encryption at rest:**
- Passwords are wrapped with PBKDF2-SHA256 at 600,000 iterations per credential
- Fingerprint wraps derive their key material from the device authenticator, so the wrapping secret lives in hardware rather than in the database
- The PIN is never persisted, so there is nothing PIN-related stored on disk

**Session PINs are ephemeral by design.** The PIN never touches disk, exists only for the current session, and vanishes when the app closes. Three wrong attempts wipes the session and returns you to a real credential.

**Unlock methods stay local.** Fingerprint, PIN, and password are how you open the vault on one specific device. They are per device and never enter a sync. Your phone can use fingerprint while your browser uses a password. Only stored website credentials move between devices.

**Design boundaries:**
- Domain names are currently stored as plaintext object keys. Encrypting the vault as a single blob is planned so the site list is not readable at rest.
- Physical access to an unlocked or in-session device is outside the threat model, as it is for any password manager. Security assumes the device itself is not compromised while in use.
- The master key is handled in memory during multi-method enrollment, which is inherent to key management in the browser without a hardware keystore. Hardware keystore binding on Android is planned.
- Fingerprint unlock requires an authenticator with WebAuthn PRF support. Devices without it use password unlock. There is no fake biometric path.

## Quick Start - Forks and Experimentation Highly Encouraged!

### Prerequisites
- Node.js 18+
- Android Studio for device builds (optional)

### Build from Source
```bash
git clone https://github.com/HiImRook/local-vault-password-manager.git
cd local-vault-password-manager
node build.js
```

Open test.html in a browser, or build for Android:

```bash
npm install
npx cap sync
npx cap open android
```

## Architecture Highlights

**Verify-by-Unwrap:**
There are no stored password or PIN hashes. Authentication is the act of deriving a wrapping key from your credential and attempting the AES-GCM unwrap. The auth tag rejects wrong keys. This means the cheapest possible offline attack is the full KDF, by construction.

**PRF-Bound Fingerprint:**
The fingerprint wrapping key is derived via HKDF from the WebAuthn PRF extension output. That output requires the physical authenticator and user verification to produce. The database contains a wrapped key and a salt, the secret ingredient is in the hardware, not the data.

**Credential Merge:**
Two paired devices reconcile their vaults credential by credential. The username identifies a login within a site, so matching usernames resolve to the newest password while different usernames coexist. The merge runs on decrypted usernames inside the unlocked session, then re-encrypts under the shared key. The app and the browser extension run the exact same merge code.

**Ephemeral Session PIN:**
The PIN is a session artifact, not a stored credential. Setting it encrypts the in-memory master key under a PIN-derived key. Inactivity nulls the raw key and keeps only the blob. Resume decrypts it. Close the app and the whole construction evaporates. The guarantee comes from the absence of the artifact.

**In-Memory Session State:**
Session state lives in plain objects and Sets. No session persistence, tokens, or cookies.

**Single-File Bundle:**
build.js assembles the source modules into one self-contained HTML file. No module loader, no CDN, no external requests at runtime.

**QR Pairing Ceremony:**
Device transfer uses ephemeral ECDH keys exchanged over QR, a numeric comparison code derived from the shared secret as a short authentication string, and AES-GCM for the transfer itself. No relay, server, or account needed.

## Related Projects

- **Valid Blockchain:** https://github.com/HiImRook/accessible-tpi-chain
- **Anonymous Memer Bot:** https://github.com/HiImRook/Anonymous-Memer-Bot

## Contributing

Contributions welcome. This project maintains a compact, readable codebase with strict architectural principles.

**Guidelines:**
- Open issue for large changes first
- Follow existing code style:
  - Zero comments (self-documenting names)
  - In-memory state management (Maps/Sets/objects)
  - Constants in SCREAMING_SNAKE_CASE
  - Complete file implementations (no fragments)
  - No new dependencies without discussion

## Security

**Vulnerability Reporting:**
Report security issues via GitHub Security Advisories.

**Audit Status:**
Pre-1.0. The v0.3.0 key protection layer was reworked against identified weaknesses in the alpha. Community review welcome. auth.js and crypto.js are the surfaces that matter.

## License

MIT License - See LICENSE file

Copyright (c) 2025-2026 Rook

## Acknowledgements

Built and maintained by Rook.

---

**"Your passwords. Your device. Your keys. Nothing given is nothing leaked."**
