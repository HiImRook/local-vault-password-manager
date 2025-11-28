import { getPasswordVault, setPasswordVault, getAuth, setAuth } from './store.js'
import { createBackupSignature, verifyBackupSignature } from './crypto.js'

const PAIRING_TIMEOUT = 60000

function generatePairingCode() {
  const code = Math.floor(1000 + Math.random() * 9000)
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
    ['encrypt', 'decrypt']
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

async function prepareTransfer(masterKey) {
  const vault = await getPasswordVault()
  const auth = await getAuth()

  if (!vault) {
    return { success: false, error: 'No vault to transfer' }
  }

  const passwordCount = Object.values(vault.credentials || {}).flat().length

  const payload = JSON.stringify({
    version: 1,
    createdAt: Date.now(),
    passwordCount,
    vault: vault,
    auth: {
      masterKey: auth.masterKey,
      fingerprintSalt: auth.fingerprintSalt || null,
      fingerprintEnabled: auth.fingerprintEnabled || false,
      fingerprintWrappedKey: auth.fingerprintWrappedKey || null,
      pinSalt: auth.pinSalt || null,
      pinHash: auth.pinHash || null,
      pinWrappedKey: auth.pinWrappedKey || null,
      passwordSalt: auth.passwordSalt || null,
      passwordHash: auth.passwordHash || null,
      passwordWrappedKey: auth.passwordWrappedKey || null
    }
  })

  const masterKeyForSig = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(auth.masterKey),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )

  const signature = await createBackupSignature(payload, masterKeyForSig)

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

async function verifyTransfer(transferData, masterKeyBytes) {
  const masterKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(masterKeyBytes),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )

  const valid = await verifyBackupSignature(transferData.payload, transferData.signature, masterKey)

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

async function receiveTransfer(transferData) {
  const data = JSON.parse(transferData.payload)

  const verification = await verifyTransfer(transferData, data.auth.masterKey)
  if (!verification.valid) {
    return { success: false, error: verification.error }
  }

  const vault = data.vault
  vault.meta.lastAccess = Date.now()
  await setPasswordVault(vault)

  await setAuth({
    masterKey: data.auth.masterKey,
    fingerprintSalt: data.auth.fingerprintSalt,
    fingerprintEnabled: data.auth.fingerprintEnabled,
    fingerprintWrappedKey: data.auth.fingerprintWrappedKey,
    pinSalt: data.auth.pinSalt,
    pinHash: data.auth.pinHash,
    pinWrappedKey: data.auth.pinWrappedKey,
    passwordSalt: data.auth.passwordSalt,
    passwordHash: data.auth.passwordHash,
    passwordWrappedKey: data.auth.passwordWrappedKey
  })

  const masterKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(data.auth.masterKey),
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )

  return {
    success: true,
    masterKey,
    imported: {
      passwordCount: verification.passwordCount
    }
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
