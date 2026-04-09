// Fixture: dpdp-tracking-ban-001 — SHOULD TRIGGER
import GoogleAnalytics from 'react-ga';
import { hotjar } from 'hotjar';
GoogleAnalytics.initialize('UA-12345678-1');
mixpanel.track('page_view', { page: '/kids-game' });
