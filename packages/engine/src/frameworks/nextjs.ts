/**
 * Next.js Framework Profile
 *
 * Next.js provides built-in protections that overlap with several COPPA rules:
 * - React JSX auto-escaping mitigates most XSS vectors
 * - HTTPS enforcement in production covers unencrypted PII transmission
 * - Next.js Link component handles external navigation safely
 * - Middleware provides centralized cookie management
 */

import { FrameworkProfile } from './types';

export const nextjsProfile: FrameworkProfile = {
  id: 'nextjs',
  name: 'Next.js',
  ecosystem: 'javascript',
  handled_rules: [
    {
      rule_id: 'coppa-sec-015',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: 'React auto-escapes JSX output by default. dangerouslySetInnerHTML is the only XSS vector and is flagged separately.',
      documentation_url: 'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html',
    },
    {
      rule_id: 'coppa-sec-006',
      action: 'suppress',
      reason: 'Next.js enforces HTTPS in production. API routes run server-side. Development HTTP is expected.',
      documentation_url: 'https://nextjs.org/docs/app/api-reference/next-config-js/headers',
    },
    {
      rule_id: 'coppa-ext-017',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: "Next.js Link component handles external navigation. rel='noopener noreferrer' is auto-added.",
      documentation_url: 'https://nextjs.org/docs/app/api-reference/components/link',
    },
    {
      rule_id: 'coppa-cookies-016',
      action: 'downgrade',
      downgrade_to: 'low',
      reason: 'Next.js middleware can intercept and manage cookies centrally.',
      documentation_url: 'https://nextjs.org/docs/app/building-your-application/routing/middleware',
    },
  ],
  safe_patterns: [
    {
      description: 'Next.js Image component for optimized, safe image handling',
      patterns: [/next\/image/, /<Image\s/],
      applies_to_rules: ['coppa-ugc-014'],
    },
    {
      description: 'Next.js middleware for centralized request/response interception',
      patterns: [/middleware\.(ts|js)/, /NextResponse/],
      applies_to_rules: ['coppa-sec-015'],
    },
  ],
};
