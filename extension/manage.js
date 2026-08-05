import * as auth from './auth.js'
import * as passwords from './passwords.js'
import * as session from './session.js'
import * as store from './store.js'

const tabs = document.querySelectorAll('.sidebar-tab')
const tabManage = document.getElementById('tab-manage')
const tabPersonal = document.getElementById('tab-personal')
const tabSettings = document.getElementById('tab-settings')
const tabAbout = document.getElementById('tab-about')

const cardFp = document.getElementById('card-fp')
const cardPin = document.getElementById('card-pin')
const cardPw = document.getElementById('card-pw')
const statusFp = document.getElementById('status-fp')
const statusPin = document.getElementById('status-pin')
const statusPw = document.getElementById('status-pw')

const btnEditFp = document.getElementById('btn-edit-fp')
const btnDelFp = document.getElementById('btn-del-fp')
const btnEditPin = document.getElementById('btn-edit-pin')
const btnDelPin = document.getElementById('btn-del-pin')
const btnEditPw = document.getElementById('btn-edit-pw')
const btnDelPw = document.getElementById('btn-del-pw')

const credentialsList = document.getElementById('credentials-list')
const msgManage = document.getElementById('msg-manage')
const msgSettings = document.getElementById('msg-settings')

const toggleLockPopup = document.getElementById('toggle-lock-popup')
const inputTimeout = document.getElementById('input-timeout')
const btnClearVault = document.getElementById('btn-clear-vault')

function showTab(tabName) {
  tabs.forEach(t => t.classList.remove('active'))
  document.querySelector(`[data-tab="${tabName}"]`).classList.add('active')
  
  tabManage.classList.add('hidden')
  tabPersonal.classList.add('hidden')
  tabSettings.classList.add('hidden')
  tabAbout.classList.add('hidden')
  
  document.getElementById('tab-' + tabName).classList.remove('hidden')
}

function showMsg(el, msg, type) {
  el.textContent = msg
  el.className = 'msg ' + type
  el.classList.remove('hidden')
  setTimeout(() => el.classList.add('hidden'), 3000)
}

async function loadAuthStatus() {
  const status = await auth.initAuth()
  
  if (status.hasFingerprint) {
    cardFp.classList.add('active')
    statusFp.textContent = 'Enrolled'
    btnEditFp.textContent = 'Edit'
  } else {
    cardFp.classList.remove('active')
    statusFp.textContent = 'Not enrolled'
    btnEditFp.textContent = 'Enroll'
  }
  
  if (status.hasPIN) {
    cardPin.classList.add('active')
    statusPin.textContent = 'Set'
    btnEditPin.textContent = 'Edit'
  } else {
    cardPin.classList.remove('active')
    statusPin.textContent = 'Not set'
    btnEditPin.textContent = 'Set'
  }
  
  if (status.hasPassword) {
    cardPw.classList.add('active')
    statusPw.textContent = 'Set'
    btnEditPw.textContent = 'Edit'
  } else {
    cardPw.classList.remove('active')
    statusPw.textContent = 'Not set'
    btnEditPw.textContent = 'Set'
  }
}

async function loadAllCredentials() {
  const domainsResult = await passwords.getAllDomains()
  if (!domainsResult.success || domainsResult.domains.length === 0) {
    credentialsList.innerHTML = '<div style="padding:24px;text-align:center;color:#666;">No saved credentials</div>'
    return
  }
  
  const domains = domainsResult.domains.sort()
  credentialsList.innerHTML = ''
  
  for (const domain of domains) {
    const vaultData = await store.getPasswordVault()
    const domainCreds = vaultData?.credentials?.[domain] || []
    
    const domainItem = document.createElement('div')
    domainItem.style.cssText = 'border-bottom:1px solid #2a2a2a;'
    
    const domainHeader = document.createElement('div')
    domainHeader.className = 'credential-item'
    domainHeader.style.cursor = 'pointer'
    domainHeader.innerHTML = 
      '<span style="color:#666;margin-right:8px;">▶</span>' +
      '<div class="credential-domain">' + escapeHtml(domain) + '</div>' +
      '<div style="flex:1;"></div>' +
      '<div style="color:#666;font-size:12px;">' + domainCreds.length + ' account' + (domainCreds.length !== 1 ? 's' : '') + '</div>'
    
    const domainContent = document.createElement('div')
    domainContent.style.cssText = 'display:none;background:#111;padding:0 16px;'
    
    domainHeader.onclick = () => {
      const isExpanded = domainContent.style.display !== 'none'
      if (isExpanded) {
        domainContent.style.display = 'none'
        domainHeader.querySelector('span').textContent = '▶'
      } else {
        domainContent.style.display = 'block'
        domainHeader.querySelector('span').textContent = '▼'
      }
    }
    
    for (let i = 0; i < domainCreds.length; i++) {
      const cred = domainCreds[i]
      const credRow = document.createElement('div')
      credRow.style.cssText = 'padding:12px 0;border-bottom:1px solid #1a1a1a;display:flex;align-items:center;gap:12px;'
      credRow.innerHTML = 
        '<div class="credential-username" style="flex:1;">Account ' + (i + 1) + '</div>' +
        '<div class="credential-password" style="width:150px;">••••••••</div>' +
        '<div class="credential-actions">' +
        '<button class="small secondary btn-show">👁️</button>' +
        '<button class="small secondary btn-edit">✏️</button>' +
        '<button class="small danger btn-delete">🗑️</button>' +
        '</div>'
      
      credRow.dataset.credId = cred.id
      credRow.dataset.credIndex = i
      
      credRow.querySelector('.btn-show').onclick = async (e) => {
        e.stopPropagation()
        const usernameEl = credRow.querySelector('.credential-username')
        const pwEl = credRow.querySelector('.credential-password')
        
        if (pwEl.textContent !== '••••••••') {
          pwEl.textContent = '••••••••'
          usernameEl.textContent = 'Account ' + (i + 1)
          return
        }
        
        let masterKey = session.getMasterKey()
        
        if (!masterKey) {
          const authResult = await promptAuth()
          if (!authResult.success) {
            showMsg(msgManage, 'Authentication required', 'error')
            return
          }
          masterKey = authResult.masterKey
          session.setMasterKey(masterKey)
        }
        
        const result = await passwords.getCredentials(domain, masterKey)
        if (result.success) {
          const credential = result.credentials.find(c => c.id === cred.id)
          if (credential) {
            usernameEl.textContent = credential.username
            pwEl.textContent = credential.password
          }
        }
      }
      
      credRow.querySelector('.btn-edit').onclick = async (e) => {
        e.stopPropagation()
        
        let masterKey = session.getMasterKey()
        
        if (!masterKey) {
          const authResult = await promptAuth()
          if (!authResult.success) {
            showMsg(msgManage, 'Authentication required to edit', 'error')
            return
          }
          masterKey = authResult.masterKey
          session.setMasterKey(masterKey)
        }
        
        showMsg(msgManage, 'Edit functionality coming soon')
      }
      
      credRow.querySelector('.btn-delete').onclick = async (e) => {
        e.stopPropagation()
        
        let masterKey = session.getMasterKey()
        
        if (!masterKey) {
          const authResult = await promptAuth()
          if (!authResult.success) {
            showMsg(msgManage, 'Authentication required to delete', 'error')
            return
          }
          masterKey = authResult.masterKey
          session.setMasterKey(masterKey)
        }
        
        const result = await passwords.getCredentials(domain, masterKey)
        if (result.success) {
          const credential = result.credentials.find(c => c.id === cred.id)
          if (credential && confirm('Delete credential for ' + credential.username + ' on ' + domain + '?')) {
            const delResult = await passwords.deleteCredential(cred.id)
            if (delResult.success) {
              showMsg(msgManage, 'Credential deleted', 'success')
              loadAllCredentials()
            } else {
              showMsg(msgManage, 'Delete failed: ' + delResult.error, 'error')
            }
          }
        }
      }
      
      domainContent.appendChild(credRow)
    }
    
    domainItem.appendChild(domainHeader)
    domainItem.appendChild(domainContent)
    credentialsList.appendChild(domainItem)
  }
}

async function promptAuth() {
  const status = await auth.initAuth()
  
  if (status.hasFingerprint) {
    const result = await auth.authenticateFingerprint()
    if (result.success) return { success: true, masterKey: result.masterKey }
  }
  
  const pin = prompt('Enter PIN:')
  if (pin) {
    const result = await auth.authenticatePIN(pin)
    if (result.success) return { success: true, masterKey: result.masterKey }
  }
  
  const pw = prompt('Enter Password:')
  if (pw) {
    const result = await auth.authenticatePassword(pw)
    if (result.success) return { success: true, masterKey: result.masterKey }
  }
  
  return { success: false }
}

function escapeHtml(str) {
  const div = document.createElement('div')
  div.textContent = str
  return div.innerHTML
}

btnEditFp.onclick = () => showMsg(msgManage, 'Fingerprint editing coming soon')
btnEditPin.onclick = () => showMsg(msgManage, 'PIN editing coming soon')
btnEditPw.onclick = () => showMsg(msgManage, 'Password editing coming soon')

btnDelFp.onclick = async () => {
  if (confirm('Delete fingerprint authentication?')) {
    const result = await auth.removeFingerprint()
    if (result.success) {
      showMsg(msgManage, 'Fingerprint removed', 'success')
      loadAuthStatus()
    } else {
      showMsg(msgManage, result.error, 'error')
    }
  }
}

btnDelPin.onclick = async () => {
  if (confirm('Delete PIN authentication?')) {
    const result = await auth.removePIN()
    if (result.success) {
      showMsg(msgManage, 'PIN removed', 'success')
      loadAuthStatus()
    } else {
      showMsg(msgManage, result.error, 'error')
    }
  }
}

btnDelPw.onclick = async () => {
  if (confirm('Delete password authentication?')) {
    const result = await auth.removePassword()
    if (result.success) {
      showMsg(msgManage, 'Password removed', 'success')
      loadAuthStatus()
    } else {
      showMsg(msgManage, result.error, 'error')
    }
  }
}

toggleLockPopup.onclick = () => {
  toggleLockPopup.classList.toggle('active')
  const enabled = toggleLockPopup.classList.contains('active')
  chrome.storage.local.set({ lockOnPopupClose: enabled })
  showMsg(msgSettings, 'Setting saved', 'success')
}

inputTimeout.onchange = () => {
  const minutes = parseInt(inputTimeout.value) || 0
  chrome.storage.local.set({ autoLockTimeout: minutes })
  showMsg(msgSettings, 'Timeout set to ' + minutes + ' minutes', 'success')
}

btnClearVault.onclick = async () => {
  const confirm1 = confirm(
    'Delete all vault data permanently?\n\n' +
    'Recommendation: Back up to another device first.\n\n' +
    'This cannot be undone.'
  )
  
  if (!confirm1) return
  
  const confirm2 = confirm('Final confirmation: This will delete everything. Continue?')
  
  if (confirm2) {
    await store.clearAll()
    session.lockAll()
    showMsg(msgSettings, 'Vault cleared. Redirecting to setup...', 'success')
    setTimeout(() => window.close(), 2000)
  }
}

tabs.forEach(tab => {
  tab.onclick = () => showTab(tab.dataset.tab)
})

async function init() {
  await loadAuthStatus()
  await loadAllCredentials()
  
  const settings = await chrome.storage.local.get(['lockOnPopupClose', 'autoLockTimeout'])
  if (settings.lockOnPopupClose) toggleLockPopup.classList.add('active')
  if (settings.autoLockTimeout) inputTimeout.value = settings.autoLockTimeout
}

init()