import {
  generateSalt,
  generateMasterKey,
  deriveKeyFromSecret,
  masterKeyToCryptoKey,
  wrapMasterKey,
  unwrapMasterKey,
  hashPin,
  hashPassword,
  arraysEqual
} from './crypto.js'
import { getAuth, setAuth } from './store.js'

const RP_NAME = 'Valid Vault'
const RP_ID = location.hostname
const FINGERPRINT_SECRET = 'valid-vault-fingerprint-auth-v1'

const attempts = new Map()
const LOCKOUT_MS = 60000
const MAX_ATTEMPTS = 3
const CREATION_TIMEOUT_MS = 60000

const creationTimers = new Map()

function checkRateLimit(type) {
  const record = attempts.get(type)
  if (!record) return { allowed: true }
  if (Date.now() - record.lastAttempt > LOCKOUT_MS) {
    attempts.delete(type)
    return { allowed: true }
  }
  if (record.count >= MAX_ATTEMPTS) {
    const remaining = Math.ceil((LOCKOUT_MS - (Date.now() - record.lastAttempt)) / 1000)
    return { allowed: false, remaining }
  }
  return { allowed: true }
}

function recordFailedAttempt(type) {
  const record = attempts.get(type) || { count: 0, lastAttempt: 0 }
  record.count++
  record.lastAttempt = Date.now()
  attempts.set(type, record)
}

function clearAttempts(type) {
  attempts.delete(type)
}

function startCreationTimer(type) {
  cancelCreationTimer(type)
  const timer = {
    startedAt: Date.now(),
    timeoutId: setTimeout(() => {
      creationTimers.delete(type)
    }, CREATION_TIMEOUT_MS)
  }
  creationTimers.set(type, timer)
  return timer.startedAt
}

function checkCreationTimer(type) {
  const timer = creationTimers.get(type)
  if (!timer) return { valid: false, error: 'Creation session expired' }
  if (Date.now() - timer.startedAt > CREATION_TIMEOUT_MS) {
    creationTimers.delete(type)
    return { valid: false, error: 'Creation session expired' }
  }
  return { valid: true, remaining: Math.ceil((CREATION_TIMEOUT_MS - (Date.now() - timer.startedAt)) / 1000) }
}

function cancelCreationTimer(type) {
  const timer = creationTimers.get(type)
  if (timer) {
    clearTimeout(timer.timeoutId)
    creationTimers.delete(type)
  }
}

function hasWrappedKeys(auth) {
  if (!auth) return false
  return !!(auth.fingerprintWrappedKey || auth.pinWrappedKey || auth.passwordWrappedKey)
}

async function migrateLegacyMasterKey() {
  const auth = await getAuth()
  if (auth && auth.masterKey) {
    delete auth.masterKey
    await setAuth(auth)
  }
}

async function initAuth() {
  const auth = await getAuth()
  return {
    hasFingerprint: !!(auth && auth.fingerprintEnabled),
    hasPIN: !!(auth && auth.pinHash),
    hasPassword: !!(auth && auth.passwordHash),
    hasVault: hasWrappedKeys(auth),
    isNew: !auth || !hasWrappedKeys(auth)
  }
}

function startFingerprintEnrollment() {
  return startCreationTimer('fingerprint')
}

async function enrollFingerprint(existingMasterKey) {
  const timerCheck = checkCreationTimer('fingerprint')
  if (!timerCheck.valid) {
    return { success: false, error: timerCheck.error }
  }

  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32))
    const userId = new TextEncoder().encode('valid-vault-user')

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: challenge,
        rp: { name: RP_NAME, id: RP_ID },
        user: {
          id: userId,
          name: 'vault-user',
          displayName: 'Vault User'
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },
          { alg: -257, type: 'public-key' }
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred'
        },
        timeout: 60000
      }
    })

    const auth = await getAuth() || {}

    if (!auth.fingerprintSalt) {
      auth.fingerprintSalt = Array.from(await generateSalt())
    }

    const salt = new Uint8Array(auth.fingerprintSalt)
    const wrappingKey = await deriveKeyFromSecret(FINGERPRINT_SECRET, salt)

    let masterKeyBytes
    let isNewVault = false

    if (existingMasterKey) {
      masterKeyBytes = existingMasterKey instanceof CryptoKey
        ? new Uint8Array(await crypto.subtle.exportKey('raw', existingMasterKey))
        : new Uint8Array(existingMasterKey)
    } else if (hasWrappedKeys(auth)) {
      return { success: false, error: 'Vault exists. Unlock first to add fingerprint.' }
    } else {
      masterKeyBytes = await generateMasterKey()
      isNewVault = true
    }

    const wrappedForFingerprint = await wrapMasterKey(masterKeyBytes, wrappingKey)
    auth.fingerprintWrappedKey = wrappedForFingerprint
    auth.fingerprintEnabled = true

    await setAuth(auth)

    const masterKey = await masterKeyToCryptoKey(masterKeyBytes)

    cancelCreationTimer('fingerprint')
    return { success: true, masterKey, isNewVault }
  } catch (error) {
    return { success: false, error: error.message }
  }
}

async function authenticateFingerprint() {
  const rateCheck = checkRateLimit('fingerprint')
  if (!rateCheck.allowed) {
    return { success: false, error: `Too many attempts. Wait ${rateCheck.remaining}s` }
  }

  try {
    const auth = await getAuth()
    if (!auth || !auth.fingerprintEnabled) {
      return { success: false, error: 'No fingerprint enrolled' }
    }

    if (!auth.fingerprintWrappedKey) {
      return { success: false, error: 'Fingerprint not configured properly' }
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32))

    await navigator.credentials.get({
      publicKey: {
        challenge: challenge,
        rpId: RP_ID,
        userVerification: 'required',
        timeout: 60000
      }
    })

    const salt = new Uint8Array(auth.fingerprintSalt)
    const unwrappingKey = await deriveKeyFromSecret(FINGERPRINT_SECRET, salt)

    const masterKey = await unwrapMasterKey(auth.fingerprintWrappedKey, unwrappingKey)

    await migrateLegacyMasterKey()

    clearAttempts('fingerprint')
    return { success: true, masterKey }
  } catch (error) {
    recordFailedAttempt('fingerprint')
    return { success: false, error: error.message }
  }
}

function startPINCreation() {
  return startCreationTimer('pin')
}

async function setPIN(pin, existingMasterKey) {
  const timerCheck = checkCreationTimer('pin')
  if (!timerCheck.valid) {
    return { success: false, error: timerCheck.error }
  }

  if (pin.length < 4 || pin.length > 6 || !/^\d+$/.test(pin)) {
    return { success: false, error: 'PIN must be 4-6 digits' }
  }

  const auth = await getAuth() || {}
  const salt = auth.pinSalt ? new Uint8Array(auth.pinSalt) : await generateSalt()
  const hash = await hashPin(pin, salt)

  auth.pinHash = hash
  auth.pinSalt = Array.from(salt)

  const wrappingKey = await deriveKeyFromSecret(pin, salt)

  let masterKeyBytes
  let isNewVault = false

  if (existingMasterKey) {
    masterKeyBytes = existingMasterKey instanceof CryptoKey
      ? new Uint8Array(await crypto.subtle.exportKey('raw', existingMasterKey))
      : new Uint8Array(existingMasterKey)
  } else if (hasWrappedKeys(auth)) {
    return { success: false, error: 'Vault exists. Unlock first to add PIN.' }
  } else {
    masterKeyBytes = await generateMasterKey()
    isNewVault = true
  }

  const wrappedForPIN = await wrapMasterKey(masterKeyBytes, wrappingKey)
  auth.pinWrappedKey = wrappedForPIN

  await setAuth(auth)

  cancelCreationTimer('pin')

  const masterKey = await masterKeyToCryptoKey(masterKeyBytes)
  return { success: true, masterKey, isNewVault }
}

function startPasswordCreation() {
  return startCreationTimer('password')
}

async function setPassword(password, existingMasterKey) {
  const timerCheck = checkCreationTimer('password')
  if (!timerCheck.valid) {
    return { success: false, error: timerCheck.error }
  }

  if (password.length < 8) {
    return { success: false, error: 'Password must be at least 8 characters' }
  }

  const auth = await getAuth() || {}
  const salt = auth.passwordSalt ? new Uint8Array(auth.passwordSalt) : await generateSalt()
  const hash = await hashPassword(password, salt)

  auth.passwordHash = hash
  auth.passwordSalt = Array.from(salt)

  const wrappingKey = await deriveKeyFromSecret(password, salt)

  let masterKeyBytes
  let isNewVault = false

  if (existingMasterKey) {
    masterKeyBytes = existingMasterKey instanceof CryptoKey
      ? new Uint8Array(await crypto.subtle.exportKey('raw', existingMasterKey))
      : new Uint8Array(existingMasterKey)
  } else if (hasWrappedKeys(auth)) {
    return { success: false, error: 'Vault exists. Unlock first to add password.' }
  } else {
    masterKeyBytes = await generateMasterKey()
    isNewVault = true
  }

  const wrappedForPassword = await wrapMasterKey(masterKeyBytes, wrappingKey)
  auth.passwordWrappedKey = wrappedForPassword

  await setAuth(auth)

  cancelCreationTimer('password')

  const masterKey = await masterKeyToCryptoKey(masterKeyBytes)
  return { success: true, masterKey, isNewVault }
}

async function authenticatePIN(pin) {
  const rateCheck = checkRateLimit('pin')
  if (!rateCheck.allowed) {
    return { success: false, error: `Too many attempts. Wait ${rateCheck.remaining}s` }
  }

  const auth = await getAuth()
  if (!auth || !auth.pinHash) {
    return { success: false, error: 'No PIN set' }
  }

  const salt = new Uint8Array(auth.pinSalt)
  const hash = await hashPin(pin, salt)

  if (!arraysEqual(hash, auth.pinHash)) {
    recordFailedAttempt('pin')
    return { success: false, error: 'Invalid PIN' }
  }

  try {
    const unwrappingKey = await deriveKeyFromSecret(pin, salt)
    const masterKey = await unwrapMasterKey(auth.pinWrappedKey, unwrappingKey)

    await migrateLegacyMasterKey()

    clearAttempts('pin')
    return { success: true, masterKey }
  } catch (error) {
    recordFailedAttempt('pin')
    return { success: false, error: 'Decryption failed' }
  }
}

async function authenticatePassword(password) {
  const rateCheck = checkRateLimit('password')
  if (!rateCheck.allowed) {
    return { success: false, error: `Too many attempts. Wait ${rateCheck.remaining}s` }
  }

  const auth = await getAuth()
  if (!auth || !auth.passwordHash) {
    return { success: false, error: 'No password set' }
  }

  const salt = new Uint8Array(auth.passwordSalt)
  const hash = await hashPassword(password, salt)

  if (!arraysEqual(hash, auth.passwordHash)) {
    recordFailedAttempt('password')
    return { success: false, error: 'Invalid password' }
  }

  try {
    const unwrappingKey = await deriveKeyFromSecret(password, salt)
    const masterKey = await unwrapMasterKey(auth.passwordWrappedKey, unwrappingKey)

    await migrateLegacyMasterKey()

    clearAttempts('password')
    return { success: true, masterKey }
  } catch (error) {
    recordFailedAttempt('password')
    return { success: false, error: 'Decryption failed' }
  }
}

async function removeFingerprint() {
  const auth = await getAuth()
  if (!auth) return { success: false, error: 'No auth configured' }

  if (!auth.pinHash && !auth.passwordHash) {
    return { success: false, error: 'Cannot remove fingerprint without PIN or password backup' }
  }

  delete auth.fingerprintEnabled
  delete auth.fingerprintWrappedKey
  await setAuth(auth)

  return { success: true }
}

async function removePIN() {
  const auth = await getAuth()
  if (!auth) return { success: false, error: 'No auth configured' }

  if (!auth.fingerprintEnabled && !auth.passwordHash) {
    return { success: false, error: 'Cannot remove PIN without fingerprint or password backup' }
  }

  delete auth.pinHash
  delete auth.pinSalt
  delete auth.pinWrappedKey
  await setAuth(auth)

  return { success: true }
}

async function removePassword() {
  const auth = await getAuth()
  if (!auth) return { success: false, error: 'No auth configured' }

  if (!auth.fingerprintEnabled && !auth.pinHash) {
    return { success: false, error: 'Cannot remove password without fingerprint or PIN backup' }
  }

  delete auth.passwordHash
  delete auth.passwordSalt
  delete auth.passwordWrappedKey
  await setAuth(auth)

  return { success: true }
}

export {
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
