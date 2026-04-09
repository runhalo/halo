// Fixture: dpdp-ad-targeting-003 — SHOULD TRIGGER
import AdMob from 'react-native-admob';
AdMob.initialize('ca-app-pub-xxxxx');
AdMob.loadAd('banner', { targeting: { childDirected: false } });
const config = { personalizedAd: true, targetAudience: 'children' };
