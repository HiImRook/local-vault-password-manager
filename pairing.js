import { getPasswordVault, setPasswordVault, getAuth, setAuth } from './store.js'
import { createBackupSignature, verifyBackupSignature } from './crypto.js'

const PAIRING_TIMEOUT = 60000

function generatePairingCode() {
  const array = new Uint32Array(1)
  crypto.getRandomValues(array)
  const code = 1000 + (array[0] % 9000)
  return code.toString()
}

function generateSessionId() {
  return crypto.randomUUID()
}

async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  )

  const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey)

  return {
    privateKey: keyPair.privateKey,
    publicKey: Array.from(new Uint8Array(publicKeyRaw))
  }
}

async function deriveSharedKey(privateKey, publicKeyRaw) {
  const publicKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(publicKeyRaw),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  )

  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  )
}

async function derivePinFromSharedKey(sharedKey) {
  const keyBytes = await crypto.subtle.exportKey('raw', sharedKey)
  const view = new DataView(keyBytes)
  const num = view.getUint32(0, true)
  return String(num % 10000).padStart(4, '0')
}

async function initiatePairing() {
  const keyPair = await generateKeyPair()
  const sessionId = generateSessionId()

  const qrData = JSON.stringify({
    type: 'valid-vault-pair',
    sessionId,
    publicKey: keyPair.publicKey
  })

  return {
    qrData,
    sessionId,
    privateKey: keyPair.privateKey,
    expiresAt: Date.now() + PAIRING_TIMEOUT
  }
}

async function respondToPairing(sourcePublicKey) {
  const keyPair = await generateKeyPair()
  const sharedKey = await deriveSharedKey(keyPair.privateKey, sourcePublicKey)
  const pin = await derivePinFromSharedKey(sharedKey)

  const responseData = JSON.stringify({
    type: 'valid-vault-pair-response',
    publicKey: keyPair.publicKey
  })

  return {
    responseData,
    sharedKey,
    pin
  }
}

async function completePairing(privateKey, targetPublicKey) {
  const sharedKey = await deriveSharedKey(privateKey, targetPublicKey)
  const pin = await derivePinFromSharedKey(sharedKey)

  return {
    sharedKey,
    pin
  }
}

async function requestPairing() {
  const code = generatePairingCode()
  const sessionId = generateSessionId()
  const keyPair = await generateKeyPair()

  return {
    code,
    sessionId,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    expiresAt: Date.now() + PAIRING_TIMEOUT
  }
}

function parseQR(qrData) {
  try {
    const data = JSON.parse(qrData)
    if (data.type !== 'valid-vault-pair') {
      return { success: false, error: 'Invalid QR code' }
    }
    return { success: true, sessionId: data.sessionId, publicKey: data.publicKey }
  } catch (error) {
    return { success: false, error: 'Invalid QR format' }
  }
}

function parseResponse(responseData) {
  try {
    const data = JSON.parse(responseData)
    if (data.type !== 'valid-vault-pair-response') {
      return { success: false, error: 'Invalid response' }
    }
    return { success: true, publicKey: data.publicKey }
  } catch (error) {
    return { success: false, error: 'Invalid response format' }
  }
}

async function wrapMasterKeyForTransfer(masterKey, sharedKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12))

  let keyToWrap = masterKey
  if (!(masterKey instanceof CryptoKey)) {
    keyToWrap = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(masterKey),
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
  }

  const wrapped = await crypto.subtle.wrapKey(
    'raw',
    keyToWrap,
    sharedKey,
    { name: 'AES-GCM', iv }
  )

  return {
    wrapped: Array.from(new Uint8Array(wrapped)),
    iv: Array.from(iv)
  }
}

async function unwrapMasterKeyFromTransfer(wrappedData, sharedKey) {
  const masterKey = await crypto.subtle.unwrapKey(
    'raw',
    new Uint8Array(wrappedData.wrapped),
    sharedKey,
    { name: 'AES-GCM', iv: new Uint8Array(wrappedData.iv) },
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )

  return masterKey
}

async function prepareTransfer(masterKey, sharedKey) {
  if (!masterKey) {
    return { success: false, error: 'Unlock vault first to transfer' }
  }

  if (!sharedKey) {
    return { success: false, error: 'Complete pairing first' }
  }

  const vault = await getPasswordVault()

  if (!vault) {
    return { success: false, error: 'No vault to transfer' }
  }

  const passwordCount = Object.values(vault.credentials || {}).flat().length

  const wrappedMasterKey = await wrapMasterKeyForTransfer(masterKey, sharedKey)

  const payloadObj = {
    version: 2,
    createdAt: Date.now(),
    passwordCount,
    vault: vault,
    wrappedMasterKey: wrappedMasterKey
  }

  const payload = JSON.stringify(payloadObj)

  let signingKey = masterKey
  if (!(masterKey instanceof CryptoKey)) {
    signingKey = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(masterKey),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
  }

  const signature = await createBackupSignature(payload, signingKey)

  return {
    success: true,
    data: {
      payload,
      signature
    },
    meta: {
      passwordCount,
      createdAt: Date.now()
    }
  }
}

async function encryptTransfer(transferData, sharedKey) {
  const encoder = new TextEncoder()
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    sharedKey,
    encoder.encode(JSON.stringify(transferData))
  )

  return {
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(ciphertext))
  }
}

async function decryptTransfer(encrypted, sharedKey) {
  const decoder = new TextDecoder()

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(encrypted.iv) },
    sharedKey,
    new Uint8Array(encrypted.ciphertext)
  )

  return JSON.parse(decoder.decode(plaintext))
}

async function verifyTransfer(transferData, masterKey) {
  let verifyKey = masterKey
  if (!(masterKey instanceof CryptoKey)) {
    verifyKey = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(masterKey),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
  }

  const valid = await verifyBackupSignature(transferData.payload, transferData.signature, verifyKey)

  if (!valid) {
    return { valid: false, error: 'Backup corrupted or tampered' }
  }

  const meta = JSON.parse(transferData.payload)
  return {
    valid: true,
    createdAt: meta.createdAt,
    passwordCount: meta.passwordCount
  }
}

async function receiveTransfer(transferData, sharedKey) {
  if (!sharedKey) {
    return { success: false, error: 'Pairing key required' }
  }

  const data = JSON.parse(transferData.payload)

  if (data.version !== 2 || !data.wrappedMasterKey) {
    return { success: false, error: 'Incompatible transfer format' }
  }

  const masterKey = await unwrapMasterKeyFromTransfer(data.wrappedMasterKey, sharedKey)

  const verification = await verifyTransfer(transferData, masterKey)
  if (!verification.valid) {
    return { success: false, error: verification.error }
  }

  const vault = data.vault
  vault.meta.lastAccess = Date.now()
  await setPasswordVault(vault)

  return {
    success: true,
    masterKey,
    imported: {
      passwordCount: verification.passwordCount
    },
    requiresAuthSetup: true
  }
}

function isExpired(expiresAt) {
  return Date.now() > expiresAt
}

export {
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
