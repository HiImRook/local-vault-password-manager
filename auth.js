import {
  PBKDF2_ITERATIONS,
  LEGACY_PBKDF2_ITERATIONS,
  generateSalt,
  generateMasterKey,
  deriveKeyFromSecret,
  deriveKeyFromPrfOutput,
  masterKeyToCryptoKey,
  wrapMasterKey,
  unwrapMasterKey
} from './crypto.js'
import { getAuth, setAuth } from './store.js'

const RP_NAME = 'Local Vault'
const RP_ID = location.hostname
const PRF_INFO = 'valid-vault-prf-wrap-v2'
const LEGACY_FINGERPRINT_SECRET = 'valid-vault-fingerprint-auth-v1'

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
  return !!(auth.fingerprintWrappedKey || auth.passwordWrappedKey || auth.pinWrappedKey)
}

async function purgeLegacyPin() {
  const auth = await getAuth()
  if (auth && (auth.pinWrappedKey || auth.pinSalt || auth.pinHash || auth.pinKdfIterations)) {
    delete auth.pinWrappedKey
    delete auth.pinSalt
    delete auth.pinHash
    delete auth.pinKdfIterations
    await setAuth(auth)
  }
}

async function migrateLegacyMasterKey() {
  const auth = await getAuth()
  if (auth && auth.masterKey) {
    delete auth.masterKey
    await setAuth(auth)
  }
}

async function resolveMasterKeyBytes(existingMasterKey, auth) {
  if (existingMasterKey) {
    const bytes = existingMasterKey instanceof CryptoKey
      ? new Uint8Array(await crypto.subtle.exportKey('raw', existingMasterKey))
      : new Uint8Array(existingMasterKey)
    return { bytes, isNewVault: false }
  }
  if (hasWrappedKeys(auth)) {
    return { error: true }
  }
  return { bytes: await generateMasterKey(), isNewVault: true }
}

async function upgradeWrap(auth, method, secret, masterKey) {
  const iterations = auth[method + 'KdfIterations'] || 0
  if (iterations >= PBKDF2_ITERATIONS && !auth[method + 'Hash']) return

  const salt = await generateSalt()
  const wrappingKey = await deriveKeyFromSecret(secret, salt)
  const masterKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', masterKey))

  auth[method + 'WrappedKey'] = await wrapMasterKey(masterKeyBytes, wrappingKey)
  auth[method + 'Salt'] = Array.from(salt)
  auth[method + 'KdfIterations'] = PBKDF2_ITERATIONS
  delete auth[method + 'Hash']

  await setAuth(auth)
}

async function initAuth() {
  const auth = await getAuth()
  return {
    hasFingerprint: !!(auth && auth.fingerprintEnabled && auth.fingerprintWrappedKey),
    hasPassword: !!(auth && auth.passwordWrappedKey),
    hasLegacyPIN: !!(auth && auth.pinWrappedKey),
    hasVault: hasWrappedKeys(auth),
    isNew: !auth || !hasWrappedKeys(auth)
  }
}

async function evaluatePrf(credentialId, prfSalt) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: RP_ID,
      allowCredentials: [{ id: credentialId, type: 'public-key' }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: prfSalt } } },
      timeout: 60000
    }
  })

  const results = assertion.getClientExtensionResults()
  if (!results.prf || !results.prf.results || !results.prf.results.first) return null
  return new Uint8Array(results.prf.results.first)
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
    const auth = await getAuth() || {}

    if (!existingMasterKey && hasWrappedKeys(auth)) {
      return { success: false, error: 'Vault exists. Unlock first to add fingerprint.' }
    }

    const prfSalt = crypto.getRandomValues(new Uint8Array(32))

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: RP_NAME, id: RP_ID },
        user: {
          id: new TextEncoder().encode('valid-vault-user'),
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
        extensions: { prf: { eval: { first: prfSalt } } },
        timeout: 60000
      }
    })

    const created = credential.getClientExtensionResults()
    const prfAtCreate = created.prf && created.prf.results && created.prf.results.first
    const prfEnabled = created.prf && created.prf.enabled

    if (!prfAtCreate && !prfEnabled) {
      return { success: false, error: 'This device cannot bind keys to biometrics. Use PIN or password instead.' }
    }

    const credentialId = new Uint8Array(credential.rawId)

    const prfOutput = prfAtCreate
      ? new Uint8Array(created.prf.results.first)
      : await evaluatePrf(credentialId, prfSalt)

    if (!prfOutput) {
      return { success: false, error: 'PRF evaluation failed' }
    }

    const wrappingKey = await deriveKeyFromPrfOutput(prfOutput, PRF_INFO)

    const resolved = await resolveMasterKeyBytes(existingMasterKey, auth)
    if (resolved.error) {
      return { success: false, error: 'Vault exists. Unlock first to add fingerprint.' }
    }

    auth.fingerprintWrappedKey = await wrapMasterKey(resolved.bytes, wrappingKey)
    auth.fingerprintCredentialId = Array.from(credentialId)
    auth.fingerprintPrfSalt = Array.from(prfSalt)
    auth.fingerprintEnabled = true
    delete auth.fingerprintSalt

    await setAuth(auth)

    const masterKey = await masterKeyToCryptoKey(resolved.bytes)

    cancelCreationTimer('fingerprint')
    return { success: true, masterKey, isNewVault: resolved.isNewVault }
  } catch (error) {
    return { success: false, error: error.message }
  }
}

async function authenticateLegacyFingerprint(auth) {
  await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: RP_ID,
      userVerification: 'required',
      timeout: 60000
    }
  })

  const salt = new Uint8Array(auth.fingerprintSalt)
  const unwrappingKey = await deriveKeyFromSecret(LEGACY_FINGERPRINT_SECRET, salt, LEGACY_PBKDF2_ITERATIONS)
  const masterKey = await unwrapMasterKey(auth.fingerprintWrappedKey, unwrappingKey)

  delete auth.fingerprintEnabled
  delete auth.fingerprintWrappedKey
  delete auth.fingerprintSalt
  await setAuth(auth)

  await migrateLegacyMasterKey()

  clearAttempts('fingerprint')
  return { success: true, masterKey, requiresReenroll: true }
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

    if (!auth.fingerprintCredentialId) {
      return await authenticateLegacyFingerprint(auth)
    }

    const credentialId = new Uint8Array(auth.fingerprintCredentialId)
    const prfSalt = new Uint8Array(auth.fingerprintPrfSalt)

    const prfOutput = await evaluatePrf(credentialId, prfSalt)
    if (!prfOutput) {
      recordFailedAttempt('fingerprint')
      return { success: false, error: 'PRF evaluation failed' }
    }

    const unwrappingKey = await deriveKeyFromPrfOutput(prfOutput, PRF_INFO)
    const masterKey = await unwrapMasterKey(auth.fingerprintWrappedKey, unwrappingKey)

    await purgeLegacyPin()
    await migrateLegacyMasterKey()

    clearAttempts('fingerprint')
    return { success: true, masterKey }
  } catch (error) {
    recordFailedAttempt('fingerprint')
    return { success: false, error: error.message }
  }
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
  const resolved = await resolveMasterKeyBytes(existingMasterKey, auth)
  if (resolved.error) {
    return { success: false, error: 'Vault exists. Unlock first to add password.' }
  }

  const salt = await generateSalt()
  const wrappingKey = await deriveKeyFromSecret(password, salt)

  auth.passwordWrappedKey = await wrapMasterKey(resolved.bytes, wrappingKey)
  auth.passwordSalt = Array.from(salt)
  auth.passwordKdfIterations = PBKDF2_ITERATIONS
  delete auth.passwordHash

  await setAuth(auth)

  cancelCreationTimer('password')

  const masterKey = await masterKeyToCryptoKey(resolved.bytes)
  return { success: true, masterKey, isNewVault: resolved.isNewVault }
}

async function authenticatePassword(password) {
  const rateCheck = checkRateLimit('password')
  if (!rateCheck.allowed) {
    return { success: false, error: `Too many attempts. Wait ${rateCheck.remaining}s` }
  }

  const auth = await getAuth()
  if (!auth || !auth.passwordWrappedKey) {
    return { success: false, error: 'No password set' }
  }

  try {
    const salt = new Uint8Array(auth.passwordSalt)
    const iterations = auth.passwordKdfIterations || LEGACY_PBKDF2_ITERATIONS
    const unwrappingKey = await deriveKeyFromSecret(password, salt, iterations)
    const masterKey = await unwrapMasterKey(auth.passwordWrappedKey, unwrappingKey)

    await upgradeWrap(auth, 'password', password, masterKey)
    await purgeLegacyPin()
    await migrateLegacyMasterKey()

    clearAttempts('password')
    return { success: true, masterKey }
  } catch (error) {
    recordFailedAttempt('password')
    return { success: false, error: 'Invalid password' }
  }
}

async function authenticateLegacyPIN(pin) {
  const rateCheck = checkRateLimit('pin')
  if (!rateCheck.allowed) {
    return { success: false, error: `Too many attempts. Wait ${rateCheck.remaining}s` }
  }

  const auth = await getAuth()
  if (!auth || !auth.pinWrappedKey) {
    return { success: false, error: 'No legacy PIN vault to migrate' }
  }

  try {
    const salt = new Uint8Array(auth.pinSalt)
    const iterations = auth.pinKdfIterations || LEGACY_PBKDF2_ITERATIONS
    const unwrappingKey = await deriveKeyFromSecret(pin, salt, iterations)
    const masterKey = await unwrapMasterKey(auth.pinWrappedKey, unwrappingKey)

    await purgeLegacyPin()
    await migrateLegacyMasterKey()

    clearAttempts('pin')
    const requiresAuthSetup = !auth.passwordWrappedKey && !auth.fingerprintWrappedKey
    return { success: true, masterKey, requiresAuthSetup }
  } catch (error) {
    recordFailedAttempt('pin')
    return { success: false, error: 'Invalid PIN' }
  }
}

async function removeFingerprint() {
  const auth = await getAuth()
  if (!auth) return { success: false, error: 'No auth configured' }

  if (!auth.passwordWrappedKey) {
    return { success: false, error: 'Cannot remove fingerprint without password backup' }
  }

  delete auth.fingerprintEnabled
  delete auth.fingerprintWrappedKey
  delete auth.fingerprintCredentialId
  delete auth.fingerprintPrfSalt
  delete auth.fingerprintSalt
  await setAuth(auth)

  return { success: true }
}

async function removePassword() {
  const auth = await getAuth()
  if (!auth) return { success: false, error: 'No auth configured' }

  if (!auth.fingerprintEnabled) {
    return { success: false, error: 'Cannot remove password without fingerprint backup' }
  }

  delete auth.passwordWrappedKey
  delete auth.passwordSalt
  delete auth.passwordKdfIterations
  delete auth.passwordHash
  await setAuth(auth)

  return { success: true }
}

export {
  initAuth,
  startFingerprintEnrollment,
  enrollFingerprint,
  authenticateFingerprint,
  startPasswordCreation,
  setPassword,
  authenticatePassword,
  authenticateLegacyPIN,
  removeFingerprint,
  removePassword,
  checkRateLimit,
  checkCreationTimer
}