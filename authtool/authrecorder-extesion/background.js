// AuthRecorder Pro - Background Script
let isRecording = false;
let currentSession = {
  startTime: null,
  requests: [],
  cookies: [],
  headers: [],
  tokens: []
};

// Token detection patterns
const tokenPatterns = {
  bearer: /Bearer\s+([a-zA-Z0-9\-._~+/]+=*)/i,
  jwt: /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/,
  csrf: /csrf[_-]token["']\s*:\s*["\']([^"\']+)["\']/i
};

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "startRecording",
    title: "Start Recording Auth Flow",
    contexts: ["all"]
  });

  chrome.contextMenus.create({
    id: "stopRecording",
    title: "Stop Recording",
    contexts: ["all"]
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "startRecording") {
    startRecording();
  } else if (info.menuItemId === "stopRecording") {
    stopRecording();
  }
});

// Message handling from popup and content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case 'getStatus':
      sendResponse({ isRecording, currentSession });
      break;
    case 'startRecording':
      startRecording();
      sendResponse({ success: true });
      break;
    case 'stopRecording':
      stopRecording();
      sendResponse({ success: true });
      break;
    case 'clearSession':
      clearSession();
      sendResponse({ success: true });
      break;
  }
  return true;
});

// Request interception
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!isRecording) return;
    
    const request = {
      timestamp: new Date().toISOString(),
      method: details.method,
      url: details.url,
      type: details.type,
      requestBody: details.requestBody
    };
    
    currentSession.requests.push(request);
    checkForTokens(details);
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// Header interception
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!isRecording) return;

    const headers = {};
    details.requestHeaders.forEach(header => {
      headers[header.name] = header.value;
      if (header.name.toLowerCase() === 'authorization') {
        checkForTokens({ type: 'header', content: header.value });
      }
    });

    currentSession.headers.push({
      timestamp: new Date().toISOString(),
      url: details.url,
      headers: headers
    });
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// Cookie monitoring
chrome.cookies.onChanged.addListener((changeInfo) => {
  if (!isRecording) return;
  
  const { cookie, removed } = changeInfo;
  currentSession.cookies.push({
    timestamp: new Date().toISOString(),
    action: removed ? 'removed' : 'added',
    cookie: {
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite
    }
  });
});

// Helper functions
function startRecording() {
  isRecording = true;
  currentSession = {
    startTime: new Date().toISOString(),
    requests: [],
    cookies: [],
    headers: [],
    tokens: []
  };
  
  // Notify all tabs that recording has started
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      chrome.tabs.sendMessage(tab.id, { action: 'recordingStarted' });
    });
  });
}

function stopRecording() {
  isRecording = false;
  currentSession.endTime = new Date().toISOString();
  
  // Save session data
  chrome.storage.local.set({
    ['session_' + Date.now()]: currentSession
  }, () => {
    // Notify all tabs that recording has stopped
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        chrome.tabs.sendMessage(tab.id, { 
          action: 'recordingStopped',
          sessionData: currentSession
        });
      });
    });
  });
}

function clearSession() {
  currentSession = {
    startTime: null,
    requests: [],
    cookies: [],
    headers: [],
    tokens: []
  };
}

function checkForTokens(data) {
  // Check various data sources for tokens
  const checkString = (str) => {
    Object.entries(tokenPatterns).forEach(([type, pattern]) => {
      const match = str.match(pattern);
      if (match) {
        currentSession.tokens.push({
          timestamp: new Date().toISOString(),
          type: type,
          value: match[1],
          source: data.type
        });
      }
    });
  };

  // Check request body
  if (data.requestBody && data.requestBody.formData) {
    Object.values(data.requestBody.formData).forEach(value => {
      value.forEach(str => checkString(str));
    });
  }

  // Check URL
  if (data.url) {
    checkString(data.url);
  }

  // Check headers
  if (data.type === 'header' && data.content) {
    checkString(data.content);
  }
}
