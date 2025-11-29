#!/usr/bin/env node
const fs = require('fs')
const path = require('path')

const dir = __dirname

function stripImportsAndExports(code) {
  let result = code
  result = result.replace(/import\s*\{[\s\S]*?\}\s*from\s*['"][^'"]+['"]\s*;?/g, '')
  result = result.replace(/import\s+\*\s+as\s+\w+\s+from\s*['"][^'"]+['"]\s*;?/g, '')
  result = result.replace(/import\s+\w+\s+from\s*['"][^'"]+['"]\s*;?/g, '')
  result = result.replace(/import\s*['"][^'"]+['"]\s*;?/g, '')
  result = result.replace(/export\s*\{[\s\S]*?\}\s*;?/g, '')
  result = result.replace(/export\s+default\s+/g, '')
  result = result.replace(/export\s+/g, '')
  return result.trim()
}

const crypto = stripImportsAndExports(fs.readFileSync(path.join(dir, 'crypto.js'), 'utf8'))
const store = stripImportsAndExports(fs.readFileSync(path.join(dir, 'store.js'), 'utf8'))
const session = stripImportsAndExports(fs.readFileSync(path.join(dir, 'session.js'), 'utf8'))
const passwords = stripImportsAndExports(fs.readFileSync(path.join(dir, 'passwords.js'), 'utf8'))
const auth = stripImportsAndExports(fs.readFileSync(path.join(dir, 'auth.js'), 'utf8'))
const pairing = stripImportsAndExports(fs.readFileSync(path.join(dir, 'pairing.js'), 'utf8'))

const bundledJS = `
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

const testHtmlPath = path.join(dir, 'test.html')
const testHtml = fs.readFileSync(testHtmlPath, 'utf8')

const scriptMatch = testHtml.match(/<script[^>]*>/)
if (!scriptMatch) {
  console.error('Could not find script tag in test.html')
  process.exit(1)
}

const scriptStart = testHtml.indexOf(scriptMatch[0])
const scriptEnd = testHtml.lastIndexOf('</script>')

if (scriptEnd === -1 || scriptEnd <= scriptStart) {
  console.error('Could not find closing script tag')
  process.exit(1)
}

const beforeScript = testHtml.substring(0, scriptStart)
const afterScript = testHtml.substring(scriptEnd + '</script>'.length)

const bundledHtml = `${beforeScript}<script>
${bundledJS}
window.vault = vault
window.pairing = pairing

window.onerror = function(msg, url, line) {
  console.error('Error:', msg, 'at line', line)
  var log = document.getElementById('log')
  if (log) log.innerHTML = '<div class="log-entry error">JS Error: ' + msg + ' (line ' + line + ')</div>' + log.innerHTML
}

document.addEventListener('DOMContentLoaded', function() {
  log('Valid Vault loaded')
  updateStatus()
})

function log(msg, type) {
  var el = document.getElementById('log')
  if (!el) return
  var entry = document.createElement('div')
  entry.className = 'log-entry' + (type ? ' ' + type : '')
  entry.textContent = new Date().toLocaleTimeString() + ' - ' + msg
  el.insertBefore(entry, el.firstChild)
}

async function updateStatus() {
  try {
    var status = await vault.auth.initAuth()
    document.getElementById('fp-status').className = 'status ' + (status.hasFingerprint ? 'active' : 'inactive')
    document.getElementById('pin-status').className = 'status ' + (status.hasPIN ? 'active' : 'inactive')
    document.getElementById('pw-status').className = 'status ' + (status.hasPassword ? 'active' : 'inactive')
    log('Status updated')
  } catch (e) {
    log('Status error: ' + e.message, 'error')
  }
}

function showModal(html) {
  var container = document.getElementById('modal-container')
  container.innerHTML = '<div class="modal"><div class="modal-content">' + html + '</div></div>'
  container.classList.remove('hidden')
}

function hideModal() {
  document.getElementById('modal-container').classList.add('hidden')
}

window.showSetFingerprint = async function() {
  vault.auth.startFingerprintEnrollment()
  log('Starting fingerprint enrollment...')
  var masterKey = vault.session.getMasterKey()
  var result = await vault.auth.enrollFingerprint(masterKey)
  if (result.success) {
    log('Fingerprint enrolled', 'success')
    vault.session.setMasterKey(result.masterKey)
  } else {
    log('Enrollment failed: ' + result.error, 'error')
  }
  updateStatus()
}

window.authFingerprint = async function() {
  log('Authenticating fingerprint...')
  var result = await vault.auth.authenticateFingerprint()
  if (result.success) {
    log('Fingerprint auth success', 'success')
    vault.session.setMasterKey(result.masterKey)
  } else {
    log('Auth failed: ' + result.error, 'error')
  }
  updateStatus()
}

window.showSetPIN = function() {
  vault.auth.startPINCreation()
  showModal('<h3>Set PIN</h3><input type="text" id="modal-pin" placeholder="4-6 digits" maxlength="6"><div style="margin-top:16px;"><button onclick="confirmSetPIN()">Set PIN</button><button onclick="hideModal()" class="secondary">Cancel</button></div>')
}

window.confirmSetPIN = async function() {
  var pin = document.getElementById('modal-pin').value
  var masterKey = vault.session.getMasterKey()
  var result = await vault.auth.setPIN(pin, masterKey)
  if (result.success) {
    log('PIN set', 'success')
    vault.session.setMasterKey(result.masterKey)
  } else {
    log('Set PIN failed: ' + result.error, 'error')
  }
  hideModal()
  updateStatus()
}

window.authPIN = async function() {
  var pin = document.getElementById('pin-input').value
  var result = await vault.auth.authenticatePIN(pin)
  if (result.success) {
    log('PIN auth success', 'success')
    vault.session.setMasterKey(result.masterKey)
  } else {
    log('Auth failed: ' + result.error, 'error')
  }
  updateStatus()
}

window.showSetPassword = function() {
  vault.auth.startPasswordCreation()
  showModal('<h3>Set Password</h3><input type="password" id="modal-password" placeholder="8+ characters"><div style="margin-top:16px;"><button onclick="confirmSetPassword()">Set Password</button><button onclick="hideModal()" class="secondary">Cancel</button></div>')
}

window.confirmSetPassword = async function() {
  var password = document.getElementById('modal-password').value
  var masterKey = vault.session.getMasterKey()
  var result = await vault.auth.setPassword(password, masterKey)
  if (result.success) {
    log('Password set', 'success')
    vault.session.setMasterKey(result.masterKey)
  } else {
    log('Set password failed: ' + result.error, 'error')
  }
  hideModal()
  updateStatus()
}

window.authPassword = async function() {
  var password = document.getElementById('password-input').value
  var result = await vault.auth.authenticatePassword(password)
  if (result.success) {
    log('Password auth success', 'success')
    vault.session.setMasterKey(result.masterKey)
  } else {
    log('Auth failed: ' + result.error, 'error')
  }
  updateStatus()
}

window.showSaveCredential = function() {
  if (!vault.session.hasMasterKey()) { log('Auth required', 'error'); return }
  var domain = document.getElementById('domain-input').value || 'example.com'
  showModal('<h3>Add Credential</h3><input type="text" id="modal-domain" value="' + domain + '" placeholder="domain"><input type="text" id="modal-login" placeholder="username"><input type="password" id="modal-password-cred" placeholder="password"><div style="margin-top:16px;"><button onclick="saveCredential()">Save</button><button onclick="hideModal()" class="secondary">Cancel</button></div>')
}

window.saveCredential = async function() {
  var masterKey = vault.session.getMasterKey()
  if (!masterKey) { log('Not authenticated', 'error'); hideModal(); return }
  var domain = document.getElementById('modal-domain').value
  var login = document.getElementById('modal-login').value
  var password = document.getElementById('modal-password-cred').value
  var result = await vault.passwords.saveCredential(domain, login, password, masterKey)
  if (result.success) {
    log('Credential saved for ' + domain, 'success')
    loadCredentials()
  } else {
    log('Save failed: ' + result.error, 'error')
  }
  hideModal()
}

window.loadCredentials = async function() {
  var masterKey = vault.session.getMasterKey()
  var domain = document.getElementById('domain-input').value
  var listEl = document.getElementById('credentials-list')
  if (!masterKey) { listEl.innerHTML = '<p style="color:#666;">Auth required</p>'; return }
  if (!domain) { listEl.innerHTML = '<p style="color:#666;">Enter domain</p>'; return }
  var result = await vault.passwords.getCredentials(domain, masterKey)
  if (!result.success) { listEl.innerHTML = '<p style="color:#e74c3c;">' + result.error + '</p>'; return }
  if (result.credentials.length === 0) { listEl.innerHTML = '<p style="color:#666;">No credentials</p>'; return }
  listEl.innerHTML = result.credentials.map(function(c) {
    return '<div class="credential-row"><span class="credential-login">' + c.username + '</span><span class="credential-pass">••••••••</span></div>'
  }).join('')
}

window.lockAll = function() {
  vault.session.lockAll()
  log('Session locked', 'success')
  updateStatus()
}

window.clearAll = async function() {
  if (!confirm('Clear all data?')) return
  await vault.store.clearAll()
  log('All data cleared', 'success')
  updateStatus()
}

window.startSecureSync = function() {
  log('Sync not implemented yet')
}
</script>${afterScript}`

fs.writeFileSync(testHtmlPath, bundledHtml)
console.log('Build complete:', new Date().toISOString())
