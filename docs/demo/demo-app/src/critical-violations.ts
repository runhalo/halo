// Critical COPPA violations

// coppa-auth-001: Social login without age gate
import { GoogleAuthProvider, signInWithPopup } from 'firebase/auth';
const googleProvider = new GoogleAuthProvider();
async function loginWithGoogle() {
  const result = await signInWithPopup(auth, googleProvider);
  return result.user;
}

// coppa-tracking-003: Facebook Pixel
!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?
n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;
n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;
t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,
document,'script','https://connect.facebook.net/en_US/fbevents.js');
fbq('init', '1234567890');
fbq('track', 'PageView');

// coppa-tracking-003: Google Analytics
(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
})(window,document,'script','https://www.google-analytics.com/analytics.js','ga');
ga('create', 'UA-XXXXX-Y', 'auto');
ga('send', 'pageview');

// coppa-ads-021: Targeted advertising to children
import AdSense from 'google-adsense';
function showPersonalizedAd(user) {
  AdSense.display({
    targeting: {
      age: user.age,
      interests: user.browsing_history,
      personalizedAds: true
    }
  });
}

// coppa-default-020: Public profile by default
function createProfile(user) {
  return {
    ...user,
    visibility: 'public', // Should be private by default
    show_age: true,
    show_location: true,
  };
}
