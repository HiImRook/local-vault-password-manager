const SALT_LENGTH = 16
const IV_LENGTH = 12
const KEY_LENGTH = 256
const MASTER_KEY_LENGTH = 32
const PBKDF2_ITERATIONS = 600000
const LEGACY_PBKDF2_ITERATIONS = 100000

async function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
}

async function generateIV() {
  return crypto.getRandomValues(new Uint8Array(IV_LENGTH))
}

async function generateMasterKey() {
  return crypto.getRandomValues(new Uint8Array(MASTER_KEY_LENGTH))
}

async function deriveKeyFromSecret(secret, salt, iterations = PBKDF2_ITERATIONS) {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    typeof secret === 'string' ? encoder.encode(secret) : secret,
    'PBKDF2',
    false,
    ['deriveKey']
  )

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
  )
}

async function deriveKeyFromPrfOutput(prfOutput, info) {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    prfOutput instanceof Uint8Array ? prfOutput : new Uint8Array(prfOutput),
    'HKDF',
    false,
    ['deriveKey']
  )

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: encoder.encode(info)
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
  )
}

async function masterKeyToCryptoKey(masterKeyBytes) {
  return crypto.subtle.importKey(
    'raw',
    masterKeyBytes,
    { name: 'AES-GCM', length: KEY_LENGTH },
    true,
    ['encrypt', 'decrypt']
  )
}

async function wrapMasterKey(masterKeyBytes, wrappingKey) {
  const iv = await generateIV()
  const masterKey = await crypto.subtle.importKey(
    'raw',
    masterKeyBytes,
    { name: 'AES-GCM', length: KEY_LENGTH },
    true,
    ['encrypt', 'decrypt']
  )

  const wrapped = await crypto.subtle.wrapKey(
    'raw',
    masterKey,
    wrappingKey,
    { name: 'AES-GCM', iv: iv }
  )

  return {
    iv: Array.from(iv),
    wrapped: Array.from(new Uint8Array(wrapped))
  }
}

async function unwrapMasterKey(wrappedData, unwrappingKey) {
  const iv = new Uint8Array(wrappedData.iv)
  const wrapped = new Uint8Array(wrappedData.wrapped)

  const masterKey = await crypto.subtle.unwrapKey(
    'raw',
    wrapped,
    unwrappingKey,
    { name: 'AES-GCM', iv: iv },
    { name: 'AES-GCM', length: KEY_LENGTH },
    true,
    ['encrypt', 'decrypt']
  )

  return masterKey
}

async function encrypt(plaintext, key) {
  const encoder = new TextEncoder()
  const iv = await generateIV()
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(plaintext)
  )

  return {
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(ciphertext))
  }
}

async function decrypt(encrypted, key) {
  const decoder = new TextDecoder()
  const iv = new Uint8Array(encrypted.iv)
  const ciphertext = new Uint8Array(encrypted.ciphertext)

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  )

  return decoder.decode(plaintext)
}

async function createBackupSignature(payload, key) {
  const encoder = new TextEncoder()
  const keyBytes = await crypto.subtle.exportKey('raw', key)

  const hmacKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )

  const signature = await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(payload))
  return Array.from(new Uint8Array(signature))
}

async function verifyBackupSignature(payload, signature, key) {
  const encoder = new TextEncoder()
  const keyBytes = await crypto.subtle.exportKey('raw', key)

  const hmacKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  )

  return crypto.subtle.verify('HMAC', hmacKey, new Uint8Array(signature), encoder.encode(payload))
}

export {
  PBKDF2_ITERATIONS,
  LEGACY_PBKDF2_ITERATIONS,
  generateSalt,
  generateIV,
  generateMasterKey,
  deriveKeyFromSecret,
  deriveKeyFromPrfOutput,
  masterKeyToCryptoKey,
  wrapMasterKey,
  unwrapMasterKey,
  encrypt,
  decrypt,
  createBackupSignature,
  verifyBackupSignature
}