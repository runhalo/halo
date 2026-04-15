/**
 * Angular Framework Profile
 *
 * Angular provides strong built-in security:
 * - Template interpolation auto-escaping (DomSanitizer)
 * - Built-in XSRF/CSRF protection in HttpClient
 * - Strict contextual escaping for URLs, styles, and HTML
 * - RouterLink handles navigation safely
 */

import { FrameworkProfile } from './types';

export const angularProfile: FrameworkProfile = {
  id: 'angular',
  name: 'Angular',
  ecosystem: 'javascript',
  handled_rules: [
    {
      rule_id: 'coppa-sec-015',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: 'Angular auto-escapes template interpolation via DomSanitizer. bypassSecurityTrust* is the explicit escape hatch.',
      documentation_url: 'https://angular.io/guide/security#preventing-cross-site-scripting-xss',
    },
    {
      rule_id: 'coppa-ext-017',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: 'Angular RouterLink provides safe internal navigation. External links can be intercepted via route guards.',
      documentation_url: 'https://angular.io/api/router/RouterLink',
    },
  ],
  safe_patterns: [
    {
      description: 'Angular DomSanitizer and template security',
      patterns: [/@angular/, /DomSanitizer/, /bypassSecurityTrust/],
      applies_to_rules: ['coppa-sec-015'],
    },
  ],
};
