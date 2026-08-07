import { encrypt, decrypt } from './crypto.js'
import { getPasswordVault, setPasswordVault } from './store.js'

function generateId() {
  return crypto.randomUUID()
}

async function ensureVault() {
  const existing = await getPasswordVault()
  if (existing) return { success: true }

  const vault = {
    meta: {
      version: 1,
      createdAt: Date.now(),
      lastAccess: Date.now()
    },
    credentials: {}
  }

  await setPasswordVault(vault)
  return { success: true }
}

function isLive(cred) {
  return !cred.deleted
}

async function saveCredential(domain, username, password, masterKey) {
  await ensureVault()
  const vault = await getPasswordVault()

  const encUsername = await encrypt(username, masterKey)
  const encPassword = await encrypt(password, masterKey)

  if (!vault.credentials[domain]) {
    vault.credentials[domain] = []
  }

  const existing = []
  for (const cred of vault.credentials[domain]) {
    if (cred.deleted) {
      existing.push(cred)
      continue
    }
    const existingUsername = await decrypt(cred.username, masterKey)
    if (existingUsername === username) continue
    existing.push(cred)
  }

  const id = generateId()
  existing.push({
    id,
    username: encUsername,
    password: encPassword,
    createdAt: Date.now(),
    updatedAt: Date.now()
  })

  vault.credentials[domain] = existing
  vault.meta.lastAccess = Date.now()

  await setPasswordVault(vault)
  return { success: true, id }
}

async function getCredentials(domain, masterKey) {
  await ensureVault()
  const vault = await getPasswordVault()

  const domainCreds = vault.credentials[domain]
  if (!domainCreds || domainCreds.length === 0) {
    return { success: true, credentials: [] }
  }

  const decrypted = []
  for (const cred of domainCreds) {
    if (cred.deleted) continue
    try {
      decrypted.push({
        id: cred.id,
        username: await decrypt(cred.username, masterKey),
        password: await decrypt(cred.password, masterKey),
        createdAt: cred.createdAt,
        updatedAt: cred.updatedAt
      })
    } catch (error) {
      return { success: false, error: 'Decryption failed' }
    }
  }

  return { success: true, credentials: decrypted }
}

async function getAllDomains() {
  await ensureVault()
  const vault = await getPasswordVault()

  const domains = []
  for (const domain of Object.keys(vault.credentials)) {
    const hasLive = vault.credentials[domain].some(isLive)
    if (hasLive) domains.push(domain)
  }

  return { success: true, domains }
}

async function updateCredential(credentialId, updates, masterKey) {
  const vault = await getPasswordVault()
  if (!vault) return { success: false, error: 'No vault' }

  for (const domain of Object.keys(vault.credentials)) {
    const creds = vault.credentials[domain]
    function matchesId(candidate) {
      return candidate.id === credentialId
    }
    const index = creds.findIndex(matchesId)

    if (index !== -1) {
      if (creds[index].deleted) return { success: false, error: 'Credential deleted' }
      if (updates.username) {
        creds[index].username = await encrypt(updates.username, masterKey)
      }
      if (updates.password) {
        creds[index].password = await encrypt(updates.password, masterKey)
      }
      creds[index].updatedAt = Date.now()
      vault.meta.lastAccess = Date.now()

      await setPasswordVault(vault)
      return { success: true }
    }
  }

  return { success: false, error: 'Credential not found' }
}

async function deleteCredential(credentialId) {
  const vault = await getPasswordVault()
  if (!vault) return { success: false, error: 'No vault' }

  for (const domain of Object.keys(vault.credentials)) {
    const creds = vault.credentials[domain]
    function matchesId(candidate) {
      return candidate.id === credentialId
    }
    const index = creds.findIndex(matchesId)

    if (index !== -1) {
      creds[index] = {
        id: creds[index].id,
        deleted: true,
        deletedAt: Date.now(),
        updatedAt: Date.now()
      }

      vault.meta.lastAccess = Date.now()
      await setPasswordVault(vault)
      return { success: true }
    }
  }

  return { success: false, error: 'Credential not found' }
}

async function autofill(domain, credentialId, masterKey) {
  const result = await getCredentials(domain, masterKey)
  if (!result.success) return result

  if (result.credentials.length === 0) {
    return { success: false, error: 'No credentials for domain' }
  }

  if (credentialId) {
    function matchesAutofillId(candidate) {
      return candidate.id === credentialId
    }
    const cred = result.credentials.find(matchesAutofillId)
    if (cred) return { success: true, username: cred.username, password: cred.password }
    return { success: false, error: 'Credential not found' }
  }

  const cred = result.credentials[0]
  return { success: true, username: cred.username, password: cred.password }
}

async function reEncryptVault(vault, oldKey, newKey) {
  const out = {
    meta: { version: vault.meta.version, createdAt: vault.meta.createdAt, lastAccess: vault.meta.lastAccess },
    credentials: {}
  }

  for (const domain of Object.keys(vault.credentials)) {
    const list = []
    for (const cred of vault.credentials[domain]) {
      if (cred.deleted) {
        list.push(cred)
        continue
      }
      const username = await decrypt(cred.username, oldKey)
      const password = await decrypt(cred.password, oldKey)
      list.push({
        id: cred.id,
        username: await encrypt(username, newKey),
        password: await encrypt(password, newKey),
        createdAt: cred.createdAt,
        updatedAt: cred.updatedAt
      })
    }
    out.credentials[domain] = list
  }

  return out
}

async function mergeVaults(localVault, incomingVault, masterKey) {
  const merged = {
    meta: {
      version: localVault.meta.version,
      createdAt: Math.min(localVault.meta.createdAt, incomingVault.meta.createdAt),
      lastAccess: Date.now()
    },
    credentials: {}
  }

  const domains = new Set([
    ...Object.keys(localVault.credentials),
    ...Object.keys(incomingVault.credentials)
  ])

  for (const domain of domains) {
    const localCreds = localVault.credentials[domain] || []
    const incomingCreds = incomingVault.credentials[domain] || []

    const byUsername = new Map()

    async function keyFor(cred) {
      if (cred.deleted) return 'tomb:' + cred.id
      try {
        return 'user:' + (await decrypt(cred.username, masterKey))
      } catch (error) {
        return 'id:' + cred.id
      }
    }

    for (const cred of [...localCreds, ...incomingCreds]) {
      const key = await keyFor(cred)
      const existing = byUsername.get(key)
      if (!existing || cred.updatedAt > existing.updatedAt) {
        byUsername.set(key, cred)
      }
    }

    const tombstones = new Map()
    for (const cred of [...localCreds, ...incomingCreds]) {
      if (cred.deleted) {
        const prev = tombstones.get(cred.id)
        if (!prev || cred.updatedAt > prev.updatedAt) tombstones.set(cred.id, cred)
      }
    }

    const result = []
    for (const cred of byUsername.values()) {
      if (cred.deleted) continue
      const tomb = tombstones.get(cred.id)
      if (tomb && tomb.updatedAt > cred.updatedAt) continue
      result.push(cred)
    }

    if (result.length > 0) merged.credentials[domain] = result
  }

  return merged
}

export {
  ensureVault,
  saveCredential,
  getCredentials,
  getAllDomains,
  updateCredential,
  deleteCredential,
  autofill,
  reEncryptVault,
  mergeVaults
}
