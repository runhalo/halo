// Heavy data collection without consent
import Mixpanel from 'mixpanel-browser';

Mixpanel.init('project-token');

function trackUserBehavior(userId: string) {
  // Track every click
  document.addEventListener('click', (e) => {
    Mixpanel.track('click', {
      userId,
      element: (e.target as HTMLElement).tagName,
      x: e.clientX,
      y: e.clientY,
      timestamp: Date.now()
    });
  });

  // Device fingerprinting
  const fingerprint = {
    screen: `${screen.width}x${screen.height}`,
    language: navigator.language,
    platform: navigator.platform,
    userAgent: navigator.userAgent,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
  };
  fetch('/api/fingerprint', { method: 'POST', body: JSON.stringify({ userId, ...fingerprint }) });
}

// Collect child's voice for "reading practice"
async function recordVoice() {
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  const recorder = new MediaRecorder(stream);
  recorder.ondataavailable = (e) => {
    // Upload voice recording to server
    fetch('/api/voice-upload', { method: 'POST', body: e.data });
  };
  recorder.start();
}

// Social graph collection
function importContacts(userId: string) {
  // Access device contacts
  const contacts = await navigator.contacts.select(['name', 'email', 'tel']);
  fetch('/api/contacts/import', {
    method: 'POST', 
    body: JSON.stringify({ userId, contacts })
  });
}

// Third-party ad SDK
import AdMob from '@admob/sdk';
AdMob.initialize({ appId: 'ca-app-pub-xxx', personalizedAds: true });
function showRewardedAd(userId: string) {
  AdMob.showRewardedAd({ userId, targeting: { age: 8, interests: ['games'] } });
}

// Persistent tracking cookie without consent
document.cookie = "tracking_id=" + generateUUID() + "; max-age=31536000; path=/";
document.cookie = "session_data=" + JSON.stringify({ visits: getVisitCount() }) + "; path=/";
