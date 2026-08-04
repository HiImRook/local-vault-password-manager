import { generateSalt, deriveKeyFromSecret, masterKeyToCryptoKey, encrypt, decrypt } from './crypto.js'

const session = {
  masterKey: null,
  softLock: null,
  resumeAttempts: 0,
  unlockedDomains: new Set(),
  lastActivity: 0,
  timeoutId: null
}

const SESSION_TIMEOUT = 300000
const MAX_RESUME_ATTEMPTS = 3

function setMasterKey(key) {
  session.masterKey = key
  session.lastActivity = Date.now()
  startTimeout()
}

function getMasterKey() {
  return session.masterKey
}

function hasMasterKey() {
  return session.masterKey !== null
}

async function setSessionPin(pin) {
  if (!session.masterKey) {
    return { success: false, error: 'Unlock vault first' }
  }

  if (pin.length < 4 || pin.length > 6 || !/^\d+$/.test(pin)) {
    return { success: false, error: 'PIN must be 4-6 digits' }
  }

  const salt = await generateSalt()
  const wrappingKey = await deriveKeyFromSecret(pin, salt)
  const masterKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', session.masterKey))
  const encryptedKey = await encrypt(JSON.stringify(Array.from(masterKeyBytes)), wrappingKey)

  session.softLock = { encryptedKey, salt }
  session.resumeAttempts = 0
  return { success: true }
}

function clearSessionPin() {
  session.softLock = null
  session.resumeAttempts = 0
}

function hasSessionPin() {
  return session.softLock !== null
}

function isSoftLocked() {
  return session.masterKey === null && session.softLock !== null
}

function softLockNow() {
  if (!session.softLock) return false
  session.masterKey = null
  session.unlockedDomains.clear()
  stopTimeout()
  return true
}

async function resumeWithPin(pin) {
  if (!session.softLock) {
    return { success: false, error: 'No session to resume' }
  }

  if (session.masterKey) {
    return { success: false, error: 'Session already unlocked' }
  }

  try {
    const unwrappingKey = await deriveKeyFromSecret(pin, session.softLock.salt)
    const decrypted = await decrypt(session.softLock.encryptedKey, unwrappingKey)
    const masterKeyBytes = new Uint8Array(JSON.parse(decrypted))
    const masterKey = await masterKeyToCryptoKey(masterKeyBytes)

    session.resumeAttempts = 0
    setMasterKey(masterKey)
    return { success: true, masterKey }
  } catch (error) {
    session.resumeAttempts++
    if (session.resumeAttempts >= MAX_RESUME_ATTEMPTS) {
      lockAll()
      return { success: false, error: 'Too many attempts. Vault locked. Unlock with password or fingerprint.' }
    }
    return { success: false, error: `Invalid PIN. ${MAX_RESUME_ATTEMPTS - session.resumeAttempts} attempts remaining` }
  }
}

function unlockDomain(domain) {
  session.unlockedDomains.add(domain)
}

function lockDomain(domain) {
  session.unlockedDomains.delete(domain)
}

function isDomainUnlocked(domain) {
  return session.unlockedDomains.has(domain)
}

function getUnlockedDomains() {
  return Array.from(session.unlockedDomains)
}

function resetActivity() {
  session.lastActivity = Date.now()
}

function checkTimeout() {
  if (!session.masterKey) return false

  const elapsed = Date.now() - session.lastActivity
  if (elapsed >= SESSION_TIMEOUT) {
    if (session.softLock) {
      softLockNow()
    } else {
      lockAll()
    }
    return true
  }

  return false
}

function startTimeout() {
  stopTimeout()
  session.timeoutId = setInterval(() => {
    if (checkTimeout()) {
      console.log('Session locked due to inactivity')
    }
  }, 10000)
}

function stopTimeout() {
  if (session.timeoutId) {
    clearInterval(session.timeoutId)
    session.timeoutId = null
  }
}

function lockAll() {
  session.masterKey = null
  session.softLock = null
  session.resumeAttempts = 0
  session.unlockedDomains.clear()
  session.lastActivity = 0
  stopTimeout()
}

function getState() {
  return {
    hasMasterKey: hasMasterKey(),
    hasSessionPin: hasSessionPin(),
    isSoftLocked: isSoftLocked(),
    unlockedDomains: getUnlockedDomains(),
    lastActivity: session.lastActivity
  }
}

export {
  setMasterKey,
  getMasterKey,
  hasMasterKey,
  setSessionPin,
  clearSessionPin,
  hasSessionPin,
  isSoftLocked,
  softLockNow,
  resumeWithPin,
  unlockDomain,
  lockDomain,
  isDomainUnlocked,
  getUnlockedDomains,
  resetActivity,
  checkTimeout,
  lockAll,
  getState
}