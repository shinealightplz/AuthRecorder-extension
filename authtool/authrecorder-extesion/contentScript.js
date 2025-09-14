// AuthRecorder Pro - Content Script
let isRecording = false;
let originalFunctions = {};

// Stealth configurations
const stealthConfig = {
  // Browser fingerprinting prevention
  webgl: {
    vendor: 'Google Inc. (Intel)',
    renderer: 'Intel Iris OpenGL Engine'
  },
  // Screen and window properties
  screen: {
    width: 1920,
    height: 1080,
    availWidth: 1920,
    availHeight: 1040,
    colorDepth: 24,
    pixelDepth: 24
  },
  // Hardware concurrency and memory
  hardware: {
    hardwareConcurrency: 8,
    deviceMemory: 8
  }
};

// Initialize stealth mode
function initializeStealth() {
  // Override WebGL fingerprinting
  const getParameterProxy = new Proxy(WebGLRenderingContext.prototype.getParameter, {
    apply: function(target, thisArg, args) {
      const param = args[0];
      if (param === 37445) { // UNMASKED_VENDOR_WEBGL
        return stealthConfig.webgl.vendor;
      }
      if (param === 37446) { // UNMASKED_RENDERER_WEBGL
        return stealthConfig.webgl.renderer;
      }
      return target.apply(thisArg, args);
    }
  });
  WebGLRenderingContext.prototype.getParameter = getParameterProxy;

  // Override screen properties
  Object.defineProperties(screen, {
    width: { value: stealthConfig.screen.width },
    height: { value: stealthConfig.screen.height },
    availWidth: { value: stealthConfig.screen.availWidth },
    availHeight: { value: stealthConfig.screen.availHeight },
    colorDepth: { value: stealthConfig.screen.colorDepth },
    pixelDepth: { value: stealthConfig.screen.pixelDepth }
  });

  // Override hardware properties
  Object.defineProperties(navigator, {
    hardwareConcurrency: { value: stealthConfig.hardware.hardwareConcurrency },
    deviceMemory: { value: stealthConfig.hardware.deviceMemory }
  });

  // Prevent automation detection
  Object.defineProperties(navigator, {
    webdriver: { value: undefined },
    automation: { value: undefined }
  });

  // Add noise to canvas fingerprinting
  const getContextProxy = new Proxy(HTMLCanvasElement.prototype.getContext, {
    apply: function(target, thisArg, args) {
      const context = target.apply(thisArg, args);
      if (args[0] === '2d') {
        const originalGetImageData = context.getImageData;
        context.getImageData = function() {
          const imageData = originalGetImageData.apply(this, arguments);
          addNoise(imageData.data);
          return imageData;
        };
      }
      return context;
    }
  });
  HTMLCanvasElement.prototype.getContext = getContextProxy;
}

// Add subtle noise to canvas data
function addNoise(data) {
  for (let i = 0; i < data.length; i += 4) {
    data[i] = data[i] + (Math.random() * 2 - 1);     // red
    data[i + 1] = data[i + 1] + (Math.random() * 2 - 1); // green
    data[i + 2] = data[i + 2] + (Math.random() * 2 - 1); // blue
  }
}

// Form detection and monitoring
function monitorForms() {
  const forms = document.getElementsByTagName('form');
  Array.from(forms).forEach(form => {
    if (!form.hasAttribute('data-auth-recorder')) {
      form.setAttribute('data-auth-recorder', 'monitored');
      form.addEventListener('submit', handleFormSubmit);
    }
  });
}

// Handle form submissions
function handleFormSubmit(event) {
  if (!isRecording) return;

  const formData = new FormData(event.target);
  const data = {
    timestamp: new Date().toISOString(),
    action: event.target.action,
    method: event.target.method,
    fields: {}
  };

  for (let [key, value] of formData.entries()) {
    // Mask sensitive fields
    if (key.toLowerCase().includes('password')) {
      value = '[MASKED]';
    }
    data.fields[key] = value;
  }

  // Send form data to background script
  chrome.runtime.sendMessage({
    action: 'formSubmitted',
    data: data
  });
}

// Initialize mutation observer for dynamic form detection
const observer = new MutationObserver((mutations) => {
  for (let mutation of mutations) {
    if (mutation.addedNodes.length) {
      monitorForms();
    }
  }
});

// Message handling from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case 'recordingStarted':
      isRecording = true;
      monitorForms();
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
      break;
    case 'recordingStopped':
      isRecording = false;
      observer.disconnect();
      break;
  }
});

// Initialize stealth features
initializeStealth();

// Initial form monitoring
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', monitorForms);
} else {
  monitorForms();
}

// Export functions for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    initializeStealth,
    monitorForms,
    handleFormSubmit,
    addNoise
  };
}
