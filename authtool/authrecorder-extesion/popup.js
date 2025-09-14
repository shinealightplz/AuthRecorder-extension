// AuthRecorder Pro - Popup Script
document.addEventListener('DOMContentLoaded', initializePopup);

// UI Elements
const elements = {
  recordingStatus: document.getElementById('recordingStatus'),
  startRecording: document.getElementById('startRecording'),
  stopRecording: document.getElementById('stopRecording'),
  clearSession: document.getElementById('clearSession'),
  requestCount: document.getElementById('requestCount'),
  cookieCount: document.getElementById('cookieCount'),
  tokenCount: document.getElementById('tokenCount'),
  browserProfile: document.getElementById('browserProfile'),
  fingerprintProtection: document.getElementById('fingerprintProtection'),
  canvasNoise: document.getElementById('canvasNoise'),
  automationHiding: document.getElementById('automationHiding'),
  exportSession: document.getElementById('exportSession'),
  exportFormat: document.getElementById('exportFormat'),
  showHelp: document.getElementById('showHelp'),
  showSettings: document.getElementById('showSettings'),
  toast: document.getElementById('toast')
};

// State management
let isRecording = false;
let currentSession = null;

async function initializePopup() {
  // Load current state
  const response = await sendMessage({ action: 'getStatus' });
  updateUI(response);

  // Add event listeners
  elements.startRecording.addEventListener('click', startRecording);
  elements.stopRecording.addEventListener('click', stopRecording);
  elements.clearSession.addEventListener('click', clearSession);
  elements.exportSession.addEventListener('click', exportSession);
  elements.showHelp.addEventListener('click', showHelp);
  elements.showSettings.addEventListener('click', showSettings);

  // Add settings change listeners
  elements.browserProfile.addEventListener('change', updateStealthSettings);
  elements.fingerprintProtection.addEventListener('change', updateStealthSettings);
  elements.canvasNoise.addEventListener('change', updateStealthSettings);
  elements.automationHiding.addEventListener('change', updateStealthSettings);

  // Load saved settings
  loadSettings();
}

// Message handling
function sendMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, resolve);
  });
}

// Recording controls
async function startRecording() {
  const response = await sendMessage({ action: 'startRecording' });
  if (response.success) {
    isRecording = true;
    updateUI({ isRecording: true });
    showToast('Recording started');
  }
}

async function stopRecording() {
  const response = await sendMessage({ action: 'stopRecording' });
  if (response.success) {
    isRecording = false;
    updateUI({ isRecording: false });
    showToast('Recording stopped');
  }
}

async function clearSession() {
  const response = await sendMessage({ action: 'clearSession' });
  if (response.success) {
    currentSession = null;
    updateUI({ currentSession: null });
    showToast('Session cleared');
  }
}

// UI updates
function updateUI(state) {
  const { isRecording, currentSession } = state;

  // Update recording status
  elements.recordingStatus.textContent = isRecording ? 'Recording' : 'Not Recording';
  elements.recordingStatus.classList.toggle('recording', isRecording);

  // Update button states
  elements.startRecording.disabled = isRecording;
  elements.stopRecording.disabled = !isRecording;
  elements.clearSession.disabled = !currentSession;
  elements.exportSession.disabled = !currentSession;

  // Update session stats
  if (currentSession) {
    elements.requestCount.textContent = currentSession.requests.length;
    elements.cookieCount.textContent = currentSession.cookies.length;
    elements.tokenCount.textContent = currentSession.tokens.length;
  } else {
    elements.requestCount.textContent = '0';
    elements.cookieCount.textContent = '0';
    elements.tokenCount.textContent = '0';
  }
}

// Settings management
async function loadSettings() {
  const settings = await chrome.storage.local.get('stealthSettings');
  if (settings.stealthSettings) {
    elements.browserProfile.value = settings.stealthSettings.browserProfile;
    elements.fingerprintProtection.checked = settings.stealthSettings.fingerprintProtection;
    elements.canvasNoise.checked = settings.stealthSettings.canvasNoise;
    elements.automationHiding.checked = settings.stealthSettings.automationHiding;
  }
}

async function updateStealthSettings() {
  const settings = {
    browserProfile: elements.browserProfile.value,
    fingerprintProtection: elements.fingerprintProtection.checked,
    canvasNoise: elements.canvasNoise.checked,
    automationHiding: elements.automationHiding.checked
  };

  await chrome.storage.local.set({ stealthSettings: settings });
  showToast('Settings updated');

  // Notify content script of settings change
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      chrome.tabs.sendMessage(tab.id, {
        action: 'updateStealthSettings',
        settings: settings
      });
    });
  });
}

// Export functionality
async function exportSession() {
  const format = elements.exportFormat.value;
  const response = await sendMessage({
    action: 'exportSession',
    format: format
  });

  if (response.success) {
    // Create and download the file
    const blob = new Blob([response.data], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `auth_session_${Date.now()}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast('Session exported successfully');
  }
}

// Help and settings dialogs
function showHelp() {
  chrome.tabs.create({
    url: chrome.runtime.getURL('help.html')
  });
}

function showSettings() {
  chrome.tabs.create({
    url: chrome.runtime.getURL('settings.html')
  });
}

// Toast notifications
function showToast(message, duration = 3000) {
  elements.toast.textContent = message;
  elements.toast.classList.add('show');
  setTimeout(() => {
    elements.toast.classList.remove('show');
  }, duration);
}

// Listen for background script updates
chrome.runtime.onMessage.addListener((message) => {
  if (message.action === 'sessionUpdate') {
    currentSession = message.session;
    updateUI({ isRecording, currentSession });
  }
});
