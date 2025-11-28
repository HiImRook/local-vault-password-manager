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

async function saveCredential(domain, username, password, masterKey) {
  await ensureVault()
  const vault = await getPasswordVault()
  
  const id = generateId()
  const encUsername = await encrypt(username, masterKey)
  const encPassword = await encrypt(password, masterKey)
  
  const credential = {
    id,
    username: encUsername,
    password: encPassword,
    createdAt: Date.now(),
    updatedAt: Date.now()
  }
  
  if (!vault.credentials[domain]) {
    vault.credentials[domain] = []
  }
  
  vault.credentials[domain].push(credential)
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
  
  return { success: true, domains: Object.keys(vault.credentials) }
}

async function updateCredential(credentialId, updates, masterKey) {
  const vault = await getPasswordVault()
  if (!vault) return { success: false, error: 'No vault' }
  
  for (const domain of Object.keys(vault.credentials)) {
    const creds = vault.credentials[domain]
    const index = creds.findIndex(c => c.id === credentialId)
    
    if (index !== -1) {
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
    const index = creds.findIndex(c => c.id === credentialId)
    
    if (index !== -1) {
      creds.splice(index, 1)
      
      if (creds.length === 0) {
        delete vault.credentials[domain]
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
    const cred = result.credentials.find(c => c.id === credentialId)
    if (cred) return { success: true, username: cred.username, password: cred.password }
    return { success: false, error: 'Credential not found' }
  }
  
  const cred = result.credentials[0]
  return { success: true, username: cred.username, password: cred.password }
}

export {
  ensureVault,
  saveCredential,
  getCredentials,
  getAllDomains,
  updateCredential,
  deleteCredential,
  autofill
}
