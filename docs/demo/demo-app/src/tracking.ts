// Analytics and tracking — multiple violations

// PII collection in forms
function collectProfileData() {
  const form = document.getElementById('profile-form');
  const data = {
    fullName: (form.querySelector('#name') as HTMLInputElement).value,
    email: (form.querySelector('#email') as HTMLInputElement).value,
    school: (form.querySelector('#school') as HTMLInputElement).value,
    birthday: (form.querySelector('#birthday') as HTMLInputElement).value,
    photo: uploadProfilePhoto(),
  };
  fetch('/api/profile', { method: 'POST', body: JSON.stringify(data) });
}

// External analytics without consent
import amplitude from 'amplitude-js';
amplitude.getInstance().init('API_KEY');
amplitude.getInstance().logEvent('page_view', { userId: getCurrentUser().id });

// Third-party tracking pixels
function loadTrackingPixels() {
  const img = new Image();
  img.src = 'https://track.example.com/pixel?uid=' + userId;
  document.body.appendChild(img);
  
  // Facebook pixel
  fbq('track', 'PageView', { user_id: userId, age_group: 'child' });
}

// Cross-site tracking
function setCrossTracker() {
  document.cookie = "cross_site_id=" + generateId() + "; domain=.example.com; path=/; SameSite=None; Secure";
  localStorage.setItem('persistent_id', generateId());
  sessionStorage.setItem('session_tracker', JSON.stringify({ visits: 1, pages: [] }));
}

// WebSocket for real-time surveillance
const ws = new WebSocket('wss://realtime.example.com/track');
ws.onopen = () => {
  setInterval(() => {
    ws.send(JSON.stringify({
      userId: currentUser.id,
      activeElement: document.activeElement?.id,
      scrollPosition: window.scrollY,
      timeOnPage: performance.now()
    }));
  }, 5000);
};

// Retention without deletion policy
function storeUserData(user: any) {
  db.userData.insert({
    userId: user.id,
    data: user,
    createdAt: new Date(),
    // No expiry, no deletion policy
  });
}
