const session = {
  masterKey: null,
  unlockedDomains: new Set(),
  lastActivity: 0,
  timeoutId: null
}

const SESSION_TIMEOUT = 300000

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
    lockAll()
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
  session.unlockedDomains.clear()
  session.lastActivity = 0
  stopTimeout()
}

function getState() {
  return {
    hasMasterKey: hasMasterKey(),
    unlockedDomains: getUnlockedDomains(),
    lastActivity: session.lastActivity
  }
}

export {
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
