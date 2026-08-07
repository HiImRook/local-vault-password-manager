# Local Vault Password Manager

A local, encrypted, QR code portable password manager. No cloud, no accounts, or sync servers. Your credentials live on your device, encrypted under keys only you can produce, and move between devices over a QR pairing ceremony.

---

> ✅ **Security Overhaul Notice — v0.3.0**
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

No cloud service holds your data. No company can be subpoenaed for it, breached for it, or shut down out from under it. You cannot leak what you never sent anywhere.

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

**Device Transfer:**
- ECDH pairing over QR code - ephemeral keys per session
- Numeric comparison code - short authentication string against MITM
- AES-GCM encrypted vault transfer with HMAC payload signature
- No relay servers - devices talk directly

**Platform:**
- Single-file web bundle - modules assembled by build.js into one self-contained HTML file
- Android via Capacitor
- Zero runtime dependencies beyond WebCrypto and IndexedDB

## Current Status: v0.3.0

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

**In Development:**
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

### Phase 3: Vault Schema Hardening 📋 (Future - v0.4.0)
- Single-blob vault encryption - site list becomes invisible at rest
- Vault format version bump with migration
- Fresh IV discipline audit across all encrypt paths

### Phase 4: Platform Hardening 📋 (Future)
- Android hardware keystore binding via Capacitor plugin
- PRF fallback strategy per device capability
- Web build parity decisions

## Security Model

**At rest, an attacker with your database faces:**
- Password wraps - 600,000 PBKDF2 iterations per guess, no shortcut
- Fingerprint wraps - key material bound to the device authenticator, absent from the database entirely
- PIN - nothing. There is nothing stored to attack.

**Session PINs are ephemeral by design.** The PIN never touches disk, exists only for the current session, and vanishes when the app closes. There is nothing stored for an attacker to extract and nothing to brute-force offline. Three wrong guesses wipes the session entirely. A fresh session means proving you hold the real credential.

**Known limitations, stated plainly:**
- Domain names in the vault are plaintext keys - an attacker with the database learns which sites you use, not your credentials. Scheduled for v0.4.0.
- During soft lock, master key material survives in memory in PIN-encrypted form - a memory-dump attacker with device access faces the 4-6 digit space. That attacker class already owns the device; the blob dies on process exit.
- Master key round-trips through extractable bytes during multi-method enrollment - unavoidable in pure WebCrypto without hardware keystore binding.
- PRF availability varies by platform. Devices without it get password unlock, not a pretend, theatre biometric. In other words, devices without biometric access will only be able to use the password feature.

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
The fingerprint wrapping key is derived via HKDF from the WebAuthn PRF extension output. That output requires the physical authenticator and user verification to produce. The database contains a wrapped key and a salt — the secret ingredient is in the hardware, not the data.

**Ephemeral Session PIN:**
The PIN is a session artifact, not a stored credential. Setting it encrypts the in-memory master key under a PIN-derived key. Inactivity nulls the raw key and keeps only the blob. Resume decrypts it. Close the app and the whole construction evaporates. The guarantee comes from the absence of the artifact.

**Zero-Comment Code:**
Self-documenting variable names eliminate need for comments. Complexity that requires explanation is unnecessary and just an extra layer of work.

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

MIT License — See LICENSE file

Copyright (c) 2025-2026 Rook

## Acknowledgements

Built and maintained by Rook.

---

**"Your passwords. Your device. Your keys. Nothing given is nothing leaked."**
