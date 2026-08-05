const DB_NAME = 'ValidVault'
const DB_VERSION = 1

let db = null

async function openDB() {
  if (db) return db
  
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    
    request.onerror = () => reject(request.error)
    
    request.onsuccess = () => {
      db = request.result
      resolve(db)
    }
    
    request.onupgradeneeded = (event) => {
      const database = event.target.result
      
      if (!database.objectStoreNames.contains('auth')) {
        database.createObjectStore('auth', { keyPath: 'id' })
      }
      
      if (!database.objectStoreNames.contains('passwords')) {
        database.createObjectStore('passwords', { keyPath: 'id' })
      }
      
      if (!database.objectStoreNames.contains('wallets')) {
        database.createObjectStore('wallets', { keyPath: 'id' })
      }
    }
  })
}

async function getStore(storeName, mode) {
  const database = await openDB()
  const tx = database.transaction(storeName, mode)
  return tx.objectStore(storeName)
}

async function get(storeName, key) {
  const store = await getStore(storeName, 'readonly')
  return new Promise((resolve, reject) => {
    const request = store.get(key)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result || null)
  })
}

async function put(storeName, data) {
  const store = await getStore(storeName, 'readwrite')
  return new Promise((resolve, reject) => {
    const request = store.put(data)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)
  })
}

async function remove(storeName, key) {
  const store = await getStore(storeName, 'readwrite')
  return new Promise((resolve, reject) => {
    const request = store.delete(key)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()
  })
}

async function getAuth() {
  return get('auth', 'primary')
}

async function setAuth(authData) {
  return put('auth', { id: 'primary', ...authData })
}

async function getPasswordVault() {
  return get('passwords', 'vault')
}

async function setPasswordVault(vaultData) {
  return put('passwords', { id: 'vault', ...vaultData })
}

async function getWalletVault() {
  return get('wallets', 'vault')
}

async function setWalletVault(vaultData) {
  return put('wallets', { id: 'vault', ...vaultData })
}

async function clearAll() {
  const database = await openDB()
  const stores = ['auth', 'passwords', 'wallets']
  
  for (const storeName of stores) {
    const tx = database.transaction(storeName, 'readwrite')
    const store = tx.objectStore(storeName)
    store.clear()
  }
}

export {
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
