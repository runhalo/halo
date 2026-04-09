/**
 * React Framework Profile
 *
 * React provides JSX auto-escaping which mitigates most XSS vectors.
 * Unlike Next.js, React does NOT provide:
 * - HTTPS enforcement (deployment-dependent)
 * - Safe link component (no built-in <Link> with rel attributes)
 * - Cookie middleware (client-side only)
 *
 * This profile is deliberately narrower than the Next.js profile.
 */

import { FrameworkProfile } from './types';

export const reactProfile: FrameworkProfile = {
  id: 'react',
  name: 'React',
  ecosystem: 'javascript',
  handled_rules: [
    {
      rule_id: 'coppa-sec-015',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: 'React auto-escapes JSX output by default. dangerouslySetInnerHTML is the only XSS vector.',
      documentation_url: 'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html',
    },
  ],
  safe_patterns: [
    {
      description: 'React JSX auto-escaping protects against reflected XSS',
      patterns: [/React/, /jsx/, /createElement/],
      applies_to_rules: ['coppa-sec-015'],
    },
  ],
};
