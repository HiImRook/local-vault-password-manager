#!/usr/bin/env node
const fs = require('fs')
const path = require('path')

const dir = __dirname

function stripExports(code) {
  return code
    .replace(/^export\s*\{[^}]*\}\s*;?\s*$/gm, '')
    .replace(/^export\s+/gm, '')
    .replace(/^import\s+.*$/gm, '')
    .trim()
}

const crypto = stripExports(fs.readFileSync(path.join(dir, 'crypto.js'), 'utf8'))
const store = stripExports(fs.readFileSync(path.join(dir, 'store.js'), 'utf8'))
const session = stripExports(fs.readFileSync(path.join(dir, 'session.js'), 'utf8'))
const passwords = stripExports(fs.readFileSync(path.join(dir, 'passwords.js'), 'utf8'))
const auth = stripExports(fs.readFileSync(path.join(dir, 'auth.js'), 'utf8'))
const pairing = stripExports(fs.readFileSync(path.join(dir, 'pairing.js'), 'utf8'))

const bundledJS = `
// Valid Vault - Bundled Build
// Generated: ${new Date().toISOString()}
// This file is auto-generated. Do not edit directly.
// Edit the source modules and run: node build.js

// === crypto.js ===
const cryptoModule = (function() {
${crypto}
return {
  generateSalt,
  generateIV,
  generateMasterKey,
  deriveKeyFromSecret,
  masterKeyToCryptoKey,
  wrapMasterKey,
  unwrapMasterKey,
  encrypt,
  decrypt,
  hashPin,
  hashPassword,
  arraysEqual,
  createBackupSignature,
  verifyBackupSignature
}
})();

// === store.js ===
const storeModule = (function() {
${store}
return {
  openDB,
  get,
  put,
  remove,
  getAuth,
  setAuth,
  getPasswordVault,
  setPasswordVault,
  getWalletVault,
  setWalletVault,
  clearAll
}
})();

// === session.js ===
const sessionModule = (function() {
${session}
return {
  setMasterKey,
  getMasterKey,
  hasMasterKey,
  unlockDomain,
  lockDomain,
  isDomainUnlocked,
  getUnlockedDomains,
  resetActivity,
  checkTimeout,
  lockAll,
  getState
}
})();

// === passwords.js ===
const passwordsModule = (function() {
const { encrypt, decrypt } = cryptoModule
const { getPasswordVault, setPasswordVault } = storeModule
${passwords}
return {
  ensureVault,
  saveCredential,
  getCredentials,
  getAllDomains,
  updateCredential,
  deleteCredential,
  autofill
}
})();

// === auth.js ===
const authModule = (function() {
const {
  generateSalt,
  generateMasterKey,
  deriveKeyFromSecret,
  masterKeyToCryptoKey,
  wrapMasterKey,
  unwrapMasterKey,
  hashPin,
  hashPassword,
  arraysEqual
} = cryptoModule
const { getAuth, setAuth } = storeModule
${auth}
return {
  initAuth,
  startFingerprintEnrollment,
  enrollFingerprint,
  authenticateFingerprint,
  startPINCreation,
  setPIN,
  startPasswordCreation,
  setPassword,
  authenticatePIN,
  authenticatePassword,
  removeFingerprint,
  removePIN,
  removePassword,
  checkRateLimit,
  checkCreationTimer
}
})();

// === pairing.js ===
const pairingModule = (function() {
const { getPasswordVault, setPasswordVault, getAuth, setAuth } = storeModule
const { createBackupSignature, verifyBackupSignature } = cryptoModule
${pairing}
return {
  generatePairingCode,
  generateSessionId,
  initiatePairing,
  respondToPairing,
  completePairing,
  requestPairing,
  parseQR,
  parseResponse,
  prepareTransfer,
  encryptTransfer,
  decryptTransfer,
  verifyTransfer,
  receiveTransfer,
  deriveSharedKey,
  derivePinFromSharedKey,
  isExpired
}
})();

// === Unified API ===
const vault = {
  crypto: cryptoModule,
  store: storeModule,
  session: sessionModule,
  passwords: passwordsModule,
  auth: authModule,
  pairing: pairingModule
}
const pairing = pairingModule
`

const testHtml = fs.readFileSync(path.join(dir, 'test.html'), 'utf8')

const scriptStartMarker = '<script type="module">'
const scriptEndMarker = '</script>'

const scriptStart = testHtml.indexOf(scriptStartMarker)
const scriptEnd = testHtml.lastIndexOf(scriptEndMarker)

if (scriptStart === -1 || scriptEnd === -1) {
  console.error('Could not find script tags in test.html')
  process.exit(1)
}

const beforeScript = testHtml.substring(0, scriptStart)
const afterScript = testHtml.substring(scriptEnd + scriptEndMarker.length)

const originalScript = testHtml.substring(scriptStart + scriptStartMarker.length, scriptEnd)

const cleanedScript = originalScript
  .replace(/import\s+\*\s+as\s+vault\s+from\s+['"]\.\/index\.js['"]\s*/g, '')
  .replace(/import\s+\*\s+as\s+pairing\s+from\s+['"]\.\/pairing\.js['"]\s*/g, '')
  .replace(/window\.vault\s*=\s*vault\s*/g, '')
  .replace(/window\.pairing\s*=\s*pairing\s*/g, '')

const bundledHtml = `${beforeScript}<script>
${bundledJS}
window.vault = vault
window.pairing = pairing
${cleanedScript}
${afterScript}`

fs.writeFileSync(path.join(dir, 'test.html'), bundledHtml)
console.log('Bundled test.html created successfully')
console.log('Source modules preserved - edit those and re-run build.js')