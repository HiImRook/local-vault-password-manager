import * as auth from './auth.js'
import * as passwords from './passwords.js'
import * as session from './session.js'
import * as store from './store.js'

const viewSetup = document.getElementById('view-setup')
const viewLocked = document.getElementById('view-locked')
const viewUnlocked = document.getElementById('view-unlocked')
const viewAdd = document.getElementById('view-add')

const setupStatusFp = document.getElementById('setup-status-fp')
const setupStatusPin = document.getElementById('setup-status-pin')
const setupStatusPw = document.getElementById('setup-status-pw')

const btnSetupFp = document.getElementById('btn-setup-fp')
const btnSkipFp = document.getElementById('btn-skip-fp')
const btnSetupPin = document.getElementById('btn-setup-pin')
const btnSetupPw = document.getElementById('btn-setup-pw')
const setupPin = document.getElementById('setup-pin')
const setupPassword = document.getElementById('setup-password')
const msgSetup = document.getElementById('msg-setup')

const statusFp = document.getElementById('status-fp')
const statusPin = document.getElementById('status-pin')
const statusPw = document.getElementById('status-pw')

const btnFingerprint = document.getElementById('btn-fingerprint')
const btnPin = document.getElementById('btn-pin')
const btnPassword = document.getElementById('btn-password')
const inputPin = document.getElementById('input-pin')
const inputPassword = document.getElementById('input-password')
const msgLocked = document.getElementById('msg-locked')

const btnLock = document.getElementById('btn-lock')
const btnExpand = document.getElementById('btn-expand')
const btnAdd = document.getElementById('btn-add')
const btnSave = document.getElementById('btn-save')
const btnCancel = document.getElementById('btn-cancel')
const currentDomain = document.getElementById('current-domain')
const credentialsList = document.getElementById('credentials-list')
const addDomain = document.getElementById('add-domain')
const addUsername = document.getElementById('add-username')
const addPassword = document.getElementById('add-password')
const msgUnlocked = document.getElementById('msg-unlocked')
const msgAdd = document.getElementById('msg-add')

let activeDomain = ''
let setupState = { hasFp: false, hasPin: false, hasPw: false }
let masterKey = null

async function persistKey() {
  try {
    const mk = session.getMasterKey()
    if (!mk) return
    const bytes = new Uint8Array(await crypto.subtle.exportKey('raw', mk))
    await chrome.storage.session.set({ masterKeyBytes: Array.from(bytes) })
  } catch (e) {}
}

function showView(view) {
  viewSetup.classList.add('hidden')
  viewLocked.classList.add('hidden')
  viewUnlocked.classList.add('hidden')
  viewAdd.classList.add('hidden')
  view.classList.remove('hidden')
}

function showMsg(el, msg, type) {
  el.textContent = msg
  el.className = 'msg' + (type ? ' ' + type : '')
  setTimeout(() => { el.textContent = '' }, 3000)
}

function updateSetupStatus() {
  setupStatusFp.className = 'status' + (setupState.hasFp ? ' active' : '')
  setupStatusPin.className = 'status' + (setupState.hasPin ? ' active' : '')
  setupStatusPw.className = 'status' + (setupState.hasPw ? ' active' : '')
  
  btnSetupPin.disabled = !setupState.hasFp
  btnSetupPw.disabled = !setupState.hasPin
  setupPin.disabled = !setupState.hasFp
  setupPassword.disabled = !setupState.hasPin
  
  if (setupState.hasFp && setupState.hasPin && setupState.hasPw) {
    showMsg(msgSetup, 'Setup complete!', 'success')
    setTimeout(() => init(), 1000)
  }
}

async function updateStatus() {
  const status = await auth.initAuth()
  if (statusFp) statusFp.className = 'status' + (status.hasFingerprint ? ' active' : '')
  if (statusPin) statusPin.className = 'status' + (status.hasPIN ? ' active' : '')
  if (statusPw) statusPw.className = 'status' + (status.hasPassword ? ' active' : '')
  return status
}

async function init() {
  const status = await updateStatus()
  
  if (session.hasMasterKey()) {
    showView(viewUnlocked)
    await loadCurrentSite()
  } else if (status.hasFingerprint || status.hasPIN || status.hasPassword) {
    showView(viewLocked)
  } else {
    showView(viewSetup)
    updateSetupStatus()
  }
}

async function getCurrentTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
  if (tabs[0] && tabs[0].url) {
    try {
      const url = new URL(tabs[0].url)
      return url.hostname
    } catch (e) {
      return ''
    }
  }
  return ''
}

async function loadCurrentSite() {
  activeDomain = await getCurrentTab()
  currentDomain.textContent = activeDomain || 'No site detected'
  
  if (!activeDomain) {
    credentialsList.innerHTML = ''
    return
  }
  
  const mk = session.getMasterKey()
  const result = await passwords.getCredentials(activeDomain, mk)
  
  if (result.success && result.credentials.length > 0) {
    credentialsList.innerHTML = ''
    for (const cred of result.credentials) {
      const item = document.createElement('div')
      item.className = 'credential-item'
      item.innerHTML = 
        '<div class="credential-domain">' + escapeHtml(cred.username) + '</div>' +
        '<div class="credential-user">••••••••</div>' +
        '<div class="credential-actions">' +
        '<button class="small secondary btn-show">👁️ Show</button>' +
        '</div>'
      item.dataset.password = cred.password
      
      item.querySelector('.btn-show').onclick = (e) => {
        const userEl = item.querySelector('.credential-user')
        if (e.target.textContent.includes('Show')) {
          userEl.textContent = cred.password
          e.target.textContent = '👁️ Hide'
        } else {
          userEl.textContent = '••••••••'
          e.target.textContent = '👁️ Show'
        }
      }
      
      credentialsList.appendChild(item)
    }
  } else {
    credentialsList.innerHTML = '<div class="msg">No credentials for this site</div>'
  }
}

function escapeHtml(str) {
  const div = document.createElement('div')
  div.textContent = str
  return div.innerHTML
}

btnSetupFp.onclick = async () => {
  auth.startFingerprintEnrollment()
  const result = await auth.enrollFingerprint(masterKey)
  if (result.success) {
    masterKey = result.masterKey
    session.setMasterKey(masterKey)
    await persistKey()
    setupState.hasFp = true
    updateSetupStatus()
    showMsg(msgSetup, 'Fingerprint enrolled', 'success')
  } else {
    showMsg(msgSetup, result.error, 'error')
  }
}

btnSkipFp.onclick = () => {
  setupState.hasFp = true
  updateSetupStatus()
  showMsg(msgSetup, 'Fingerprint skipped', 'success')
}

btnSetupPin.onclick = async () => {
  const pin = setupPin.value
  if (pin.length < 4 || pin.length > 6) {
    showMsg(msgSetup, 'PIN must be 4-6 digits', 'error')
    return
  }
  if (!/^\d+$/.test(pin)) {
    showMsg(msgSetup, 'PIN must be numbers only', 'error')
    return
  }
  
  auth.startPINCreation()
  const result = await auth.setPIN(pin, masterKey)
  if (result.success) {
    masterKey = result.masterKey
    session.setMasterKey(masterKey)
    await persistKey()
    setupState.hasPin = true
    setupPin.value = ''
    updateSetupStatus()
    showMsg(msgSetup, 'PIN set', 'success')
  } else {
    showMsg(msgSetup, result.error, 'error')
  }
}

btnSetupPw.onclick = async () => {
  const pw = setupPassword.value
  if (pw.length < 8) {
    showMsg(msgSetup, 'Password must be 8+ characters', 'error')
    return
  }
  
  auth.startPasswordCreation()
  const result = await auth.setPassword(pw, masterKey)
  if (result.success) {
    masterKey = result.masterKey
    session.setMasterKey(masterKey)
    await persistKey()
    setupState.hasPw = true
    setupPassword.value = ''
    updateSetupStatus()
    showMsg(msgSetup, 'Password set', 'success')
  } else {
    showMsg(msgSetup, result.error, 'error')
  }
}

btnFingerprint.onclick = async () => {
  const result = await auth.authenticateFingerprint()
  if (result.success) {
    session.setMasterKey(result.masterKey)
    await persistKey()
    await updateStatus()
    showView(viewUnlocked)
    await loadCurrentSite()
  } else {
    showMsg(msgLocked, result.error, 'error')
  }
}

btnPin.onclick = async () => {
  const pin = inputPin.value
  const result = await auth.authenticatePIN(pin)
  if (result.success) {
    session.setMasterKey(result.masterKey)
    await persistKey()
    inputPin.value = ''
    await updateStatus()
    showView(viewUnlocked)
    await loadCurrentSite()
  } else {
    showMsg(msgLocked, result.error, 'error')
  }
}

btnPassword.onclick = async () => {
  const pw = inputPassword.value
  const result = await auth.authenticatePassword(pw)
  if (result.success) {
    session.setMasterKey(result.masterKey)
    await persistKey()
    inputPassword.value = ''
    await updateStatus()
    showView(viewUnlocked)
    await loadCurrentSite()
  } else {
    showMsg(msgLocked, result.error, 'error')
  }
}

btnLock.onclick = () => {
  session.lockAll()
  try { chrome.storage.session.remove('masterKeyBytes') } catch (e) {}
  updateStatus()
  showView(viewLocked)
  credentialsList.innerHTML = ''
}

btnExpand.onclick = () => {
  chrome.tabs.create({ url: 'manage.html' })
}

btnAdd.onclick = async () => {
  addDomain.value = activeDomain
  addUsername.value = ''
  addPassword.value = ''
  showView(viewAdd)
}

btnCancel.onclick = () => {
  showView(viewUnlocked)
}

btnSave.onclick = async () => {
  const domain = addDomain.value
  const username = addUsername.value
  const password = addPassword.value
  const mk = session.getMasterKey()
  
  if (!domain || !username || !password) {
    showMsg(msgAdd, 'All fields required', 'error')
    return
  }
  
  const result = await passwords.saveCredential(domain, username, password, mk)
  if (result.success) {
    showView(viewUnlocked)
    await loadCurrentSite()
    showMsg(msgUnlocked, 'Saved', 'success')
  } else {
    showMsg(msgAdd, result.error, 'error')
  }
}

inputPin.onkeydown = (e) => { if (e.key === 'Enter') btnPin.click() }
inputPassword.onkeydown = (e) => { if (e.key === 'Enter') btnPassword.click() }
setupPin.onkeydown = (e) => { if (e.key === 'Enter') btnSetupPin.click() }
setupPassword.onkeydown = (e) => { if (e.key === 'Enter') btnSetupPw.click() }

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getCredentialsForDomain') {
    const masterKey = session.getMasterKey()
    if (!masterKey) {
      sendResponse({ success: false, credentials: [] })
      return
    }
    
    passwords.getCredentials(request.domain, masterKey).then(result => {
      sendResponse(result)
    })
    return true
  }
  
  if (request.action === 'openManage') {
    chrome.tabs.create({ url: 'manage.html' })
    sendResponse({ success: true })
  }
})
init()