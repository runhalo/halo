/**
 * Vue.js Framework Profile
 *
 * Vue provides template auto-escaping which mitigates XSS vectors.
 * v-html is the explicit escape hatch (similar to React's dangerouslySetInnerHTML).
 * Vue Router provides safe navigation handling.
 */

import { FrameworkProfile } from './types';

export const vueProfile: FrameworkProfile = {
  id: 'vue',
  name: 'Vue.js',
  ecosystem: 'javascript',
  handled_rules: [
    {
      rule_id: 'coppa-sec-015',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: 'Vue auto-escapes template interpolation by default. v-html is the only XSS vector.',
      documentation_url: 'https://vuejs.org/guide/best-practices/security.html#rule-no-1-never-use-non-trusted-templates',
    },
    {
      rule_id: 'coppa-ext-017',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: 'Vue Router can be configured to handle external navigation with guards.',
      documentation_url: 'https://router.vuejs.org/guide/advanced/navigation-guards.html',
    },
  ],
  safe_patterns: [
    {
      description: 'Vue template auto-escaping protects against XSS',
      patterns: [/Vue/, /createApp/, /\.vue$/],
      applies_to_rules: ['coppa-sec-015'],
    },
  ],
};
